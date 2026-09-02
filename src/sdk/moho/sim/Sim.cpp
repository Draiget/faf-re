#include "Sim.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "SimDriver.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include <Windows.h>
#include <intrin.h>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiBuilderImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/CUserSoundManager.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/command/CCommandDb.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/sim/BuildQueueCommandDecrement.h"
#include "moho/sim/CDamage.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CVarAccess.h"
#include "moho/debug/RDebugOverlayClass.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/EntityPositionWatchEntry.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "lua/LuaRuntimeTypes.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/CWldMap.h"
#include "moho/task/CLuaTask.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/BlueprintLoaderContext.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "gpg/core/containers/BitArray2D.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/PathPreviewFinder.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/math/Vector3f.h"
#include "moho/containers/BVSet.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/UserArmy.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/ui/CUIManager.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/EIntelTypeInfo.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;
using EntId = std::int32_t;

std::uint8_t moho::ren_Steering = 0;
bool moho::sim_KeepAllLogFiles = false;
bool moho::sim_ShowDamage = false;

namespace moho
{
  /**
   * Address: 0x004A47C0 (FUN_004A47C0, REF_CreateEditDialog)
   *
   * What it does:
   * Opens reflection edit dialog for one referenced object and name context.
   */
  void REF_CreateEditDialog(const gpg::RRef& objectRef, const char* objectName);

  /**
   * Address: 0x004A4920 (FUN_004A4920, REF_UpdateMD5)
   *
   * What it does:
   * Walks a reflected value tree, emits optional textual trace output, and
   * folds deterministic value bytes/shape into the provided MD5 context.
   */
  void REF_UpdateMD5(gpg::MD5Context* md5, gpg::RRef* ref, FILE* traceFile, std::size_t indentDepth);

  /**
   * Runtime payload attached to tree-list items in the reference editor.
   */
  class CRefTreeItemData final : public wxTreeItemDataRuntime
  {
  public:
    /**
     * Address: 0x004A3CB0 (FUN_004A3CB0)
     *
     * What it does:
     * Captures one reflected object reference and edit metadata for a tree row.
     */
    CRefTreeItemData(const gpg::RRef& ref, bool editable, const msvc8::string& pathText);

    /**
     * Address: 0x004A3D30 (FUN_004A3D30)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for tree-item ref payloads.
     */
    static CRefTreeItemData* DeleteWithFlag(CRefTreeItemData* object, std::uint8_t deleteFlags) noexcept;

    gpg::RRef mRef{};
    std::uint8_t mEditable = 0;
    std::uint8_t mPadding11To13[0x3]{};
    msvc8::string mPathText{};
    std::uint8_t mUnknown30 = 0;
    std::uint8_t mPadding31To33[0x3]{};
  };

  static_assert(sizeof(CRefTreeItemData) == 0x34, "CRefTreeItemData size must be 0x34");

  struct RFieldVectorRuntimeView
  {
    void* mProxy = nullptr;
    gpg::RField* mFirst = nullptr;
  };

  /**
   * Reflection debug dialog that visualizes and edits `gpg::RRef` trees.
   */
  class WRefEditDialog final : public wxDialogRuntime
  {
  public:
    /**
     * Address: 0x004A3DB0 (FUN_004A3DB0)
     * Mangled: ??0WRefEditDialog@Moho@@QAE@@Z
     *
     * What it does:
     * Builds one reference-edit dialog, populates the initial tree root, and
     * installs the tree-list control layout.
     */
    WRefEditDialog(const gpg::RRef& rootRef, const char* objectName);

    /**
     * Address: 0x004A3DA0 (FUN_004A3DA0)
     *
     * What it does:
     * Returns the static event-table lane for this dialog runtime type.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004A40E0 (FUN_004A40E0)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for ref-edit dialog lanes.
     */
    static WRefEditDialog* DeleteWithFlag(WRefEditDialog* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x004A4100 (FUN_004A4100)
     *
     * What it does:
     * Runs non-deleting teardown for ref-edit dialog lanes.
     */
    static WRefEditDialog* DestroyWithoutDelete(WRefEditDialog* object) noexcept;

    /**
     * Address: 0x004A4110 (FUN_004A4110)
     *
     * What it does:
     * Appends one reflected reference node under `parentItem` (or root) and
     * attaches row metadata.
     */
    [[nodiscard]] wxTreeItemIdRuntime AppendRefItem(
      const wxTreeItemIdRuntime& parentItem,
      const msvc8::string& pathText,
      const gpg::RRef& ref,
      bool editable
    );

    /**
     * Address: 0x004A4260 (FUN_004A4260)
     *
     * What it does:
     * Materializes field/index children for one reflected reference row.
     */
    void PopulateRefChildren(const gpg::RRef& ref, const wxTreeItemIdRuntime& parentItem);

    /**
     * Address: 0x004A45C0 (FUN_004A45C0)
     *
     * What it does:
     * Applies one edited lexical value to the active tree row and normalizes
     * the displayed value text from reflection output.
     */
    void ApplyCurrentValue(const wxStringRuntime& valueText);

    /**
     * Address: 0x004A4710 (FUN_004A4710)
     *
     * What it does:
     * Handles tree end-label-edit commit by writing lexical text when edit is
     * not cancelled.
     */
    void OnTreeEndLabelEdit(const wxTreeEventRuntime& event);

    static wxEventTable sm_eventTable;

    wxTreeListCtrlRuntime* mTreeControl = nullptr;
    wxTreeItemIdRuntime mActiveItem{};
  };

  static_assert(sizeof(WRefEditDialog) == 0x178, "WRefEditDialog size must be 0x178");
  static_assert(offsetof(WRefEditDialog, mTreeControl) == 0x170, "WRefEditDialog::mTreeControl offset must be 0x170");
  static_assert(offsetof(WRefEditDialog, mActiveItem) == 0x174, "WRefEditDialog::mActiveItem offset must be 0x174");

  struct CPrfTimeLogItem
  {
    const char* messageFormat = nullptr;
    std::uint32_t reserved0 = 0;
    double scale = 0.0;
    gpg::time::Timer timer{};

    /**
     * Address: 0x004A3580 (FUN_004A3580, ??1CPrfTimeLogItem@Moho@@QAE@XZ)
     *
     * What it does:
     * Logs one scoped profile duration using the configured scale factor.
     */
    ~CPrfTimeLogItem();
  };

#if defined(_M_IX86)
  static_assert(sizeof(CPrfTimeLogItem) == 0x18, "CPrfTimeLogItem size must be 0x18");
#endif
} // namespace moho

/**
 * Address: 0x004A3580 (FUN_004A3580, ??1CPrfTimeLogItem@Moho@@QAE@XZ)
 *
 * What it does:
 * Logs one scoped profile duration using the configured scale factor.
 */
moho::CPrfTimeLogItem::~CPrfTimeLogItem()
{
  gpg::Logf(messageFormat, gpg::time::CyclesToSeconds(timer.ElapsedCycles()) * scale);
}

wxEventTable moho::WRefEditDialog::sm_eventTable = {nullptr, nullptr};

namespace
{
  [[nodiscard]] wxStringRuntime BorrowUtf8AsWxString(const char* const text)
  {
    static thread_local std::wstring scratch;
    scratch = gpg::STR_Utf8ToWide(text != nullptr ? text : "");
    return wxStringRuntime::Borrow(scratch.c_str());
  }

  [[nodiscard]] wxStringRuntime BorrowUtf8AsWxString(const msvc8::string& text)
  {
    return BorrowUtf8AsWxString(text.c_str());
  }

  /**
   * Address: 0x004A4870 (FUN_004A4870)
   *
   * What it does:
   * Returns one indexed `RField` lane from a vector-like runtime field view.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RField* ResolveFieldVectorElement(
    moho::RFieldVectorRuntimeView* const fieldVector,
    const int index
  ) noexcept
  {
    if (fieldVector == nullptr || fieldVector->mFirst == nullptr || index < 0) {
      return nullptr;
    }
    return fieldVector->mFirst + index;
  }
} // namespace

/**
 * Address: 0x004A3CB0 (FUN_004A3CB0)
 *
 * What it does:
 * Captures one reflected object reference and edit metadata for a tree row.
 */
moho::CRefTreeItemData::CRefTreeItemData(
  const gpg::RRef& ref,
  const bool editable,
  const msvc8::string& pathText
)
  : wxTreeItemDataRuntime()
  , mRef(ref)
  , mEditable(editable ? 1u : 0u)
  , mPathText(pathText)
{
  mPayload = nullptr;
  mUnknown30 = 0;
}

/**
 * Address: 0x004A3D30 (FUN_004A3D30)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-item ref payloads.
 */
moho::CRefTreeItemData* moho::CRefTreeItemData::DeleteWithFlag(
  CRefTreeItemData* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->mPathText.clear();
  object->ResetClientDataBaseVTable();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A3DB0 (FUN_004A3DB0)
 * Mangled: ??0WRefEditDialog@Moho@@QAE@@Z
 *
 * What it does:
 * Builds one reference-edit dialog, populates the initial tree root, and
 * installs the tree-list control layout.
 */
moho::WRefEditDialog::WRefEditDialog(const gpg::RRef& rootRef, const char* const objectName)
  : wxDialogRuntime(
      nullptr,
      -1,
      BorrowUtf8AsWxString(objectName),
      wxPoint{-1, -1},
      wxSize{640, 480},
      0x20000840L,
      wxStringRuntime::Borrow(L"dialog")
    )
{
  mTreeControl = new wxTreeListCtrlRuntime(
    this,
    -1,
    wxPoint{-1, -1},
    wxSize{0, 0},
    0x2E09L,
    wxStringRuntime::Borrow(L"treelistctrl")
  );
  if (mTreeControl == nullptr) {
    return;
  }

  mTreeControl->AddColumn(wxStringRuntime::Borrow(L"Property"), 200u, true, 0u);
  mTreeControl->AddColumn(wxStringRuntime::Borrow(L"Value"), 200u, false, 0u);
  mTreeControl->AddColumn(wxStringRuntime::Borrow(L"Description"), 600u, false, 0u);

  const wxTreeItemIdRuntime rootItem = AppendRefItem(wxTreeItemIdRuntime{}, msvc8::string(""), rootRef, true);
  mTreeControl->Expand(rootItem);
  (void)Layout();
}

/**
 * Address: 0x004A3DA0 (FUN_004A3DA0)
 *
 * What it does:
 * Returns the static event-table lane for this dialog runtime type.
 */
const void* moho::WRefEditDialog::GetEventTable() const
{
  return &sm_eventTable;
}

/**
 * Address: 0x004A40E0 (FUN_004A40E0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for ref-edit dialog lanes.
 */
moho::WRefEditDialog* moho::WRefEditDialog::DeleteWithFlag(
  WRefEditDialog* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  DestroyWithoutDelete(object);
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A4100 (FUN_004A4100)
 *
 * What it does:
 * Runs non-deleting teardown for ref-edit dialog lanes.
 */
moho::WRefEditDialog* moho::WRefEditDialog::DestroyWithoutDelete(WRefEditDialog* const object) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  if (object->mTreeControl != nullptr) {
    wxTreeListCtrlRuntime::DeleteWithFlag(object->mTreeControl, 1u);
    object->mTreeControl = nullptr;
  }

  wxDialogRuntime::DeleteWithFlag(static_cast<wxDialogRuntime*>(object), 0u);
  return object;
}

/**
 * Address: 0x004A4110 (FUN_004A4110)
 *
 * What it does:
 * Appends one reflected reference node under `parentItem` (or root) and
 * attaches row metadata.
 */
wxTreeItemIdRuntime moho::WRefEditDialog::AppendRefItem(
  const wxTreeItemIdRuntime& parentItem,
  const msvc8::string& pathText,
  const gpg::RRef& ref,
  const bool editable
)
{
  wxTreeItemIdRuntime outItem{};
  if (mTreeControl == nullptr) {
    return outItem;
  }

  const wxStringRuntime treeText = BorrowUtf8AsWxString(pathText);
  outItem = parentItem.IsValid() ? mTreeControl->AppendItem(parentItem, treeText) : mTreeControl->AddRoot(treeText);

  auto* const itemData = new CRefTreeItemData(ref, editable, pathText);
  mTreeControl->SetItemData(outItem, itemData);

  bool hasChildren = false;
  if (ref.mType != nullptr) {
    hasChildren = ref.mType->fields_.size() > 0u;
    if (!hasChildren && ref.GetCount() > 0u) {
      hasChildren = true;
    }
  }
  if (hasChildren) {
    mTreeControl->SetItemHasChildren(outItem, true);
  }

  return outItem;
}

/**
 * Address: 0x004A4260 (FUN_004A4260)
 *
 * What it does:
 * Materializes field/index children for one reflected reference row.
 */
void moho::WRefEditDialog::PopulateRefChildren(const gpg::RRef& ref, const wxTreeItemIdRuntime& parentItem)
{
  if (mTreeControl == nullptr) {
    return;
  }

  if (ref.mType != nullptr) {
    const int fieldCount = ref.GetNumFields();
    if (fieldCount > 0) {
      RFieldVectorRuntimeView fieldView{};
      fieldView.mFirst = ref.mType->fields_.begin();

      for (int fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
        gpg::RField* const field = ResolveFieldVectorElement(&fieldView, fieldIndex);
        if (field == nullptr) {
          continue;
        }

        const gpg::RRef fieldRef = ref.GetField(fieldIndex);
        const char* const fieldName = field->mName != nullptr ? field->mName : "";
        const bool fieldEditable = (field->v4 & 0x3) == 0x3;

        const wxTreeItemIdRuntime childItem =
          AppendRefItem(parentItem, msvc8::string(fieldName), fieldRef, fieldEditable);
        mTreeControl->SetItemText(childItem, 1u, BorrowUtf8AsWxString(fieldRef.GetLexical()));

        const char* const fieldDesc = field->mDesc != nullptr ? field->mDesc : "";
        mTreeControl->SetItemText(childItem, 2u, BorrowUtf8AsWxString(fieldDesc));
      }
    }
  }

  const std::size_t indexedCount = ref.GetCount();
  if (indexedCount == 0u) {
    return;
  }

  const auto* const parentData = static_cast<CRefTreeItemData*>(mTreeControl->GetItemData(parentItem));
  const bool indexedEditable = parentData != nullptr && parentData->mEditable != 0;

  for (std::size_t index = 0; index < indexedCount; ++index) {
    const msvc8::string indexedPath = gpg::STR_Printf("[%d] = ", static_cast<int>(index));
    const gpg::RRef indexedRef = ref[static_cast<unsigned int>(index)];
    (void)AppendRefItem(parentItem, indexedPath, indexedRef, indexedEditable);
  }
}

/**
 * Address: 0x004A45C0 (FUN_004A45C0)
 *
 * What it does:
 * Applies one edited lexical value to the active tree row and normalizes the
 * displayed value text from reflection output.
 */
void moho::WRefEditDialog::ApplyCurrentValue(const wxStringRuntime& valueText)
{
  if (mTreeControl == nullptr || !mActiveItem.IsValid()) {
    return;
  }

  auto* const itemData = static_cast<CRefTreeItemData*>(mTreeControl->GetItemData(mActiveItem));
  if (itemData == nullptr) {
    return;
  }

  const msvc8::string lexicalInput = valueText.ToUtf8();
  itemData->mRef.SetLexical(lexicalInput.c_str());
  mTreeControl->SetItemText(mActiveItem, 1u, BorrowUtf8AsWxString(itemData->mRef.GetLexical()));
}

/**
 * Address: 0x004A4710 (FUN_004A4710)
 *
 * What it does:
 * Handles tree end-label-edit commit by writing lexical text when edit is not
 * cancelled.
 */
void moho::WRefEditDialog::OnTreeEndLabelEdit(const wxTreeEventRuntime& event)
{
  if (mTreeControl == nullptr || event.IsEditCancelled()) {
    return;
  }

  wxTreeItemIdRuntime eventItem{};
  event.GetItem(&eventItem);
  auto* const itemData = static_cast<CRefTreeItemData*>(mTreeControl->GetItemData(eventItem));
  if (itemData == nullptr) {
    return;
  }

  const msvc8::string lexicalInput = event.mLabel.ToUtf8();
  itemData->mRef.SetLexical(lexicalInput.c_str());
}

/**
 * Address: 0x004A47C0 (FUN_004A47C0, REF_CreateEditDialog)
 *
 * What it does:
 * Opens reflection edit dialog for one referenced object and name context.
 */
void moho::REF_CreateEditDialog(const gpg::RRef& objectRef, const char* const objectName)
{
  auto* const dialog = new WRefEditDialog(objectRef, objectName);
  if (dialog != nullptr) {
    (void)dialog->Show(true);
  }
}

namespace
{
  [[nodiscard]] msvc8::string BuildMd5TraceIndent(const std::size_t indentDepth)
  {
    msvc8::string indent{};
    (void)indent.resize(indentDepth * 2u, ' ');
    return indent;
  }

  void PrintMd5TraceLexical(FILE* const traceFile, const std::size_t indentDepth, const msvc8::string& lexical)
  {
    if (traceFile == nullptr) {
      return;
    }

    const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s%s\n", indent.c_str(), lexical.c_str());
  }

  void PrintMd5TraceFieldPrefix(FILE* const traceFile, const std::size_t indentDepth, const char* const fieldName)
  {
    if (traceFile == nullptr) {
      return;
    }

    const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s%s:\n", indent.c_str(), fieldName != nullptr ? fieldName : "");
  }

  void PrintMd5TraceIndexPrefix(FILE* const traceFile, const std::size_t indentDepth, const std::uint32_t index)
  {
    if (traceFile == nullptr) {
      return;
    }

    const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s[%u]:\n", indent.c_str(), index);
  }

  /**
   * Address: 0x004A48A0 (FUN_004A48A0)
   *
   * What it does:
   * Returns one indexed reflected field descriptor from `RType::fields_`.
   */
  [[nodiscard]] gpg::RField* ResolveTypeFieldByIndex(gpg::RType* const type, const int index) noexcept
  {
    if (type == nullptr || index < 0) {
      return nullptr;
    }

    gpg::RField* const firstField = type->fields_.begin();
    if (firstField == nullptr) {
      return nullptr;
    }

    return firstField + index;
  }

  /**
   * Address: 0x004A4E10 (FUN_004A4E10)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `char`.
   */
  [[nodiscard]] gpg::RType* GetCharRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(char));
    }
    return sType;
  }

  /**
   * Address: 0x004A4E30 (FUN_004A4E30)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `short`.
   */
  [[nodiscard]] gpg::RType* GetShortRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(short));
    }
    return sType;
  }

  /**
   * Address: 0x004A4E50 (FUN_004A4E50)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `int`.
   */
  [[nodiscard]] gpg::RType* GetIntRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(int));
    }
    return sType;
  }

  /**
   * Address: 0x004A4E70 (FUN_004A4E70)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `long`.
   */
  [[nodiscard]] gpg::RType* GetLongRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(long));
    }
    return sType;
  }

  /**
   * Address: 0x004A4E90 (FUN_004A4E90)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `signed char`.
   */
  [[nodiscard]] gpg::RType* GetSignedCharRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(signed char));
    }
    return sType;
  }

  /**
   * Address: 0x004A4EB0 (FUN_004A4EB0)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `unsigned char`.
   */
  [[nodiscard]] gpg::RType* GetUnsignedCharRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(unsigned char));
    }
    return sType;
  }

  /**
   * Address: 0x004A4ED0 (FUN_004A4ED0)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for `bool`.
   */
  [[nodiscard]] gpg::RType* GetBoolRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(bool));
    }
    return sType;
  }

  /**
   * Address: 0x004A4EF0 (FUN_004A4EF0)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI lane for legacy `msvc8::string`.
   */
  [[nodiscard]] gpg::RType* GetStringRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(msvc8::string));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* GetFloatRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(float));
    }
    return sType;
  }
} // namespace

/**
 * Address: 0x004A4920 (FUN_004A4920, REF_UpdateMD5)
 *
 * What it does:
 * Walks a reflected value tree, emits optional textual trace output, and
 * folds deterministic value bytes/shape into the provided MD5 context.
 */
void moho::REF_UpdateMD5(
  gpg::MD5Context* const md5,
  gpg::RRef* const ref,
  FILE* const traceFile,
  const std::size_t indentDepth
)
{
  if (md5 == nullptr || ref == nullptr || ref->mType == nullptr) {
    return;
  }

  gpg::RType* const refType = ref->mType;
  const bool isPrimitiveLike =
    refType == GetCharRType() || refType == GetShortRType() || refType == GetIntRType() || refType == GetLongRType()
    || refType == GetSignedCharRType() || refType == GetUnsignedCharRType() || refType == GetFloatRType()
    || refType == GetBoolRType() || refType->IsEnumType() != nullptr;

  if (isPrimitiveLike) {
    PrintMd5TraceLexical(traceFile, indentDepth, ref->GetLexical());
    md5->Update(ref->mObj, static_cast<std::size_t>(refType->size_));
    return;
  }

  if (refType == GetStringRType()) {
    const auto* const stringValue = static_cast<const msvc8::string*>(ref->mObj);
    if (stringValue != nullptr) {
      PrintMd5TraceLexical(traceFile, indentDepth, ref->GetLexical());
      md5->Update(stringValue->c_str(), stringValue->size() + 1u);
    } else {
      static const char kEmpty = '\0';
      md5->Update(&kEmpty, 1u);
    }
    return;
  }

  const std::size_t fieldCount = refType->fields_.size();
  for (std::size_t fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
    gpg::RField* const field = ResolveTypeFieldByIndex(refType, static_cast<int>(fieldIndex));
    if (field == nullptr) {
      continue;
    }

    PrintMd5TraceFieldPrefix(traceFile, indentDepth, field->mName);

    gpg::RRef fieldRef{};
    fieldRef.mObj = reinterpret_cast<std::uint8_t*>(ref->mObj) + field->mOffset;
    fieldRef.mType = field->mType;
    REF_UpdateMD5(md5, &fieldRef, traceFile, indentDepth + 1u);
  }

  if (const gpg::RIndexed* const pointerType = refType->IsPointer(); pointerType != nullptr) {
    const std::uint32_t pointerCount = static_cast<std::uint32_t>(pointerType->GetCount(ref->mObj));
    md5->Update(&pointerCount, sizeof(pointerCount));

    if (pointerCount != 0u) {
      gpg::RRef pointedRef = pointerType->SubscriptIndex(ref->mObj, 0);
      REF_UpdateMD5(md5, &pointedRef, traceFile, indentDepth);
    } else if (traceFile != nullptr) {
      const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
      std::fprintf(traceFile, "%s<NULL>\n", indent.c_str());
    }
    return;
  }

  const gpg::RIndexed* const indexedType = refType->IsIndexed();
  if (indexedType == nullptr) {
    return;
  }

  const std::uint32_t indexedCount = static_cast<std::uint32_t>(indexedType->GetCount(ref->mObj));
  md5->Update(&indexedCount, sizeof(indexedCount));

  for (std::uint32_t index = 0; index < indexedCount; ++index) {
    PrintMd5TraceIndexPrefix(traceFile, indentDepth, index);
    gpg::RRef indexedRef = indexedType->SubscriptIndex(ref->mObj, static_cast<int>(index));
    REF_UpdateMD5(md5, &indexedRef, traceFile, indentDepth + 1u);
  }
}

namespace
{
  constexpr CommandSourceId kInvalidCommandSource = 0xFF;
  // Placeholder owner id stamped into a freshly appended extra-data record
  // before the unit fills it in; the engine-wide "no entity" EntId marker.
  constexpr EntId kUnsetExtraUnitDataOwnerId = static_cast<EntId>(0xF0000000u);
  constexpr const char* kEndGameHelpText = "Signal the end of the game.  Acts like a permanent pause.";
  constexpr const char* kIsGameOverHelpText = "Return true if the game is over (i.e. EndGame() has been called).";
  constexpr const char* kEntityAttachToHelpText = "Entity:AttachTo(entity, bone)";
  constexpr const char* kEntitySetOrientationHelpText = "Entity:SetOrientation(orientation, immediately )";
  constexpr const char* kEntitySetPositionHelpText = "Entity:SetPosition(vector,[immediate])";
  constexpr const char* kEntityGetPositionHelpText = "Entity:GetPosition([bone_name])";
  constexpr const char* kEntityGetPositionXYZHelpText = "Entity:GetPositionXYZ([bone_name])";
  constexpr const char* kEntityAttachFailureError = "Failed to attach entity %s to %s on bone %d";
  constexpr const char* kEntityGetCollisionExtentsHelpText = "Entity:GetCollisionExtents()";
  constexpr const char* kEntityIsIntelEnabledHelpText = "IsIntelEnabled(type)";
  constexpr const char* kEntityIsIntelEnabledInitWarning = "EnableIntel called before InitIntel";
  constexpr const char* kEntityEnableIntelHelpText = "EnableIntel(type)";
  constexpr const char* kEntityEnableIntelInitWarning = "EnableIntel called before InitIntel";
  constexpr const char* kEntityDisableIntelHelpText = "Intel:DisableIntel(type)";
  constexpr const char* kEntityDisableIntelInitWarning = "DisableIntel called before InitIntel";
  constexpr const char* kEntitySetIntelRadiusHelpText = "SetRadius(type,radius)";
  constexpr const char* kEntitySetIntelRadiusInitWarning = "SetIntelRadius called before InitIntel";
  constexpr const char* kEntityGetIntelRadiusHelpText = "GetIntelRadius(type)";
  constexpr const char* kEntityGetIntelRadiusInitWarning = "GetIntelRadius called before InitIntel";
  constexpr const char* kEntityInitIntelHelpText = "InitIntel(army,type,<radius>)";
  constexpr const char* kEntityInitIntelRadiusWarning = "Intel type requires a radius > 0.";
  constexpr const char* kEntityInitIntelUnknownArmyWarning = "Unknown army";
  constexpr const char* kEntityAddShooterHelpText = "AddShooter(shooter)";
  constexpr const char* kEntityRemoveShooterHelpText = "RemoveShooter(shooter)";
  constexpr const char* kCreatePropHelpText = "CreateProp(location,prop_blueprint_id)";
  constexpr const char* kCreateUnitAtMouseHelpText = "CreateUnitAtMouse";
  constexpr const char* kEntityCreatePropAtBoneHelpText = "Entity:CreatePropAtBone(boneindex,prop_blueprint_id)";
  constexpr const char* kCreateResourceDepositHelpText = "type, x, y, z, size";
  constexpr const char* kEngineStartSplashScreensHelpText =
    "EngineStartSplashScreens() - kill current UI and start splash screens";
  constexpr const char* kEngineStartFrontEndUIHelpText =
    "EngineStartFrontEndUI() - kill current UI and start main menu from top";
  constexpr const char* kExitApplicationHelpText = "ExitApplication - request that the application shut down";
  constexpr const char* kExitGameHelpText = "ExitGame() - Quits the sim, but not the app";
  constexpr const char* kExecLuaInSimHelpText = "Execute some lua code in the sim";
  constexpr const char* kSimCallbackHelpText =
    "SimCallback(callback[,bool]): Execute a lua function in sim\n"
    "callback = {\n"
    "   Func    =   function name (in the SimCallbacks.lua module) to call\n"
    "   Args    =   Arguments as a lua object\n"
    "}\n"
    "If bool is specified and true, sends the current selection with the command\n";
  constexpr const char* kGetSelectedUnitsHelpText = "table GetSelectedUnits() - return a table of the currently selected units";
  constexpr const char* kGetValidAttackingUnitsHelpText =
    "table GetValidAttackingUnits() - return a table of the currently selected units";
  constexpr const char* kSelectUnitsHelpText = "Select the specified units";
  constexpr const char* kAddSelectUnitsHelpText = "Add these units to the currently Selected lists";
  constexpr const char* kGetUnitCommandFromCommandCapErrorHelpText = "string GetUnitCommandFromCommandCap(string)";
  constexpr const char* kGetUnitCommandFromCommandCapHelpText =
    "string GetUnitCommandFromCommandCap(string) - given a RULEUCC type command, return the equivalent UNITCOMMAND command";
  constexpr const char* kUnknownResourceDepositTypeMessage = "unknown resource deposit type: %s";
  constexpr const char* kGetEconomyTotalsHelpText = "table GetEconomyTotals()";
  constexpr const char* kGetEconomyTotalsMissingSessionWarning =
    "Attempt to call GetEconomyTotals before world sessions exists.";
  constexpr const char* kGetResourceSharingHelpText = "bool GetResourceSharing()";
  constexpr const char* kGetCurrentUIStateHelpText =
    "state GetCurrentUIState() - returns 'splash', 'frontend' or 'game' depending on the current state of the ui";
  constexpr const char* kGetMouseWorldPosUserHelpText = "vector GetMouseWorldPos()";
  constexpr const char* kGetMouseScreenPosHelpText = "vector GetMouseScreenPos()";
  constexpr const char* kSetFocusArmyUserHelpText = "SetFocusArmy(armyIndex or -1)";
  constexpr const char* kGetFocusArmyUserHelpText = "GetFocusArmy()";
  constexpr const char* kIsObserverHelpText = "IsObserver()";
  constexpr const char* kGetGameTimeSecondsSimHelpText =
    "Get the current game time in seconds. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGetGameTickHelpText =
    "Get the current game time in ticks. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGetSystemTimeSecondsOnlyForProfileUseHelpText =
    "float GetSystemTimeSecondsOnlyForProfileUse() - returns System time in seconds";
  constexpr const char* kGetGameTimeSecondsUserHelpText = "float GetGameTimeSeconds() - returns game time in seconds";
  constexpr const char* kGetSystemTimeSecondsHelpText =
    "float GetSystemTimeSeconds() - returns System time in seconds";
  constexpr const char* kGetSimRateHelpText = "number GetSimRate()";
  constexpr const char* kGetArmiesTableHelpText = "armyInfo GetArmiesTable()";
  constexpr const char* kGetArmyScoreHelpText = "int GetArmyScore(armyIndex)";
  constexpr const char* kDeleteCommandHelpText = "DeleteCommand(id)";
  constexpr const char* kGetSpecialFilesHelpText =
    "table GetSpecialFiles(string type)- returns a table of strings which are the names of files in special locations (currently SaveFile, Replay)";
  constexpr const char* kGetSpecialFolderHelpText = "string GetSpecialFolder(string type)";
  constexpr const char* kGetSpecialFilePathHelpText =
    "string GetSpecialFilePath(string profilename, string filename, string type) - Given the base name of a special file, retuns the complete path";
  constexpr const char* kRemoveSpecialFileHelpText =
    "RemoveSpecialFile(string profilename, string basename, string type) - remove a profile based file from the disc";
  constexpr const char* kGetSpecialFileInfoHelpText =
    "table GetSpecialFileInfo(string profileName, string basename, string type) - get information on a profile based file, nil if unable to find";
  constexpr const char* kRestartSessionHelpText = "RestartSession() - Restart the current mission/skirmish/etc";
  constexpr const char* kGetFrameHelpText = "frame GetFrame(int head) - return the root UI frame for a given head";
  constexpr const char* kClearFrameHelpText =
    "ClearFrame(int head) - destroy all controls in frame, nil head will clear all frames";
  constexpr const char* kGetNumRootFramesHelpText =
    "int GetNumRootFrames() - returns the current number of root frames (typically one per head";
  constexpr const char* kCallbackPacketMessage = "Callback packet received, exit sync is over";
  constexpr const char* kDiscardedPointerMessage = "Discarded: %p";
  constexpr const char* kRecvPointerMessage = "recv Ptr: %p";
  constexpr const char* kGetSimTicksPerSecondHelpText = "int GetSimTicksPerSecond()";
  constexpr const char* kSessionRequestPauseHelpText = "Pause the world simulation.";
  constexpr const char* kSessionResumeHelpText = "Resume the world simulation.";
  constexpr const char* kSessionIsPausedHelpText = "Return true iff the session is paused.";
  constexpr const char* kSessionIsGameOverHelpText = "Return true iff the session has been won or lost yet.";
  constexpr const char* kSessionGetLocalCommandSourceHelpText =
    "Return the local command source.  Returns 0 if the local client can't issue commands.";
  constexpr const char* kSessionIsReplayUserHelpText = "Return true iff the active session is a replay session.";
  constexpr const char* kSessionIsBeingRecordedHelpText = "Return true iff the active session is a being recorded.";
  constexpr const char* kSessionIsMultiplayerHelpText = "Return true iff the active session is a multiplayer session.";
  constexpr const char* kSessionIsObservingAllowedHelpText =
    "Return true iff observing is allowed in the active session.";
  constexpr const char* kSessionCanRestartHelpText = "Return true iff the active session can be restarted.";
  constexpr const char* kSessionIsActiveHelpText = "Return true iff there is a session currently running";
  constexpr const char* kSessionGetScenarioInfoHelpText =
    "Return the table of scenario info that was originally passed to the sim on launch.";
  constexpr const char* kSessionIsPausedNoActiveSessionText = "SessionIsPaused(): no active session.";
  constexpr const char* kSessionIsGameOverNoActiveSessionText = "SessionIsGameOver(): no active session.";
  constexpr const char* kSessionGetLocalCommandSourceNoActiveSessionText =
    "SessionGetLocalCommandSource(): no active session.";
  constexpr const char* kSessionRequestPauseNoActiveSessionText = "SessionRequestPause(): no active session.";
  constexpr const char* kSessionResumeNoActiveSessionText = "SessionResume(): no active session.";
  constexpr const char* kSessionGetScenarioInfoNoActiveSessionText = "no active session.";
  constexpr const char* kWrongLuaStateText = "wrong lua state.";
  constexpr const char* kRandomSimHelpText = "Random([[min,] max])";
  constexpr const char* kSelectedUnitHelpText =
    "unit = SelectedUnit() -- Returns the currently selected unit. For use at the lua console, so you can call Lua methods on a unit.";
  constexpr const char* kSimConExecuteHelpText = "SimConExecute('command string') -- Perform a console command";
  constexpr const char* kTryCopyPoseHelpText = "TryCopyPose(unitFrom,entityTo,bCopyWorldTransform)";
  constexpr const char* kFlattenMapRectName = "FlattenMapRect";
  constexpr const char* kFlattenMapRectHelpText = "FlattenRect(x, z, sizex, sizez, elevation)";
  constexpr const char* kFlattenMapRectOutsideBoundaryWarning =
    "Attempted to flatten terrain outside map boundary! Operation Failed!";
  constexpr const char* kParseEntityCategorySimHelpText = "parse a string to generate a new entity category";
  constexpr const char* kFlushIntelInRectHelpText = "FlushIntelInRect( minX, minZ, maxX, maxZ )";
  constexpr const char* kEntityCategoryCountAroundPositionHelpText =
    "Count how many units fit the specified category around a position";
  constexpr const char* kIsEntityHelpText = "bool = IsEntity(object)";
  constexpr const char* kIsUnitHelpText = "Unit = IsUnit(entity)";
  constexpr const char* kIsPropHelpText = "Prop = IsProp(entity)";
  constexpr const char* kIsBlipHelpText = "Blip = IsBlip(entity)";
  constexpr const char* kIsProjectileHelpText = "Projectile = IsProjectile(entity)";
  constexpr const char* kIsCollisionBeamHelpText = "CollisionBeam = IsCollisionBeam(entity)";
  constexpr const char* kDebugGetSelectionHelpText = "Get DEBUG info for UI selection";
  constexpr const char* kRandomUserHelpText = "Random([[min,] max])";
  constexpr const char* kPrintSimHelpText = "Print a log message";
  constexpr const char* kWorldIsLoadingHelpText = "bool = WorldIsLoading()";
  constexpr const char* kWorldIsPlayingHelpText = "bool = WorldIsPlaying()";
  constexpr const char* kGetGameSpeedHelpText = "Return the current game speed";
  constexpr const char* kSetGameSpeedHelpText = "Set the desired game speed";
  constexpr const char* kAddToSessionExtraSelectListHelpText = "Add unit to the session extra select list";
  constexpr const char* kRemoveFromSessionExtraSelectListHelpText = "Remove unit from the session extra select list";
  constexpr const char* kClearSessionExtraSelectListHelpText = "Clear the session extra select list";
  constexpr const char* kGetAttachedUnitsListHelpText = "Get a list of units blueprint attached to transports";
  constexpr const char* kGetAssistingUnitsListHelpText = "Get a list of units assisting me";
  constexpr const char* kGetArmyAvatarsHelpText = "table GetArmyAvatars() - return a table of avatar units for the army";
  constexpr const char* kGetIdleEngineersHelpText =
    "table GetIdleEngineers() - return a table of idle engineer units for the army";
  constexpr const char* kGetIdleFactoriesHelpText =
    "table GetIdleFactories() - return a table of idle factory units for the army";
  constexpr const char* kSyncPlayableRectHelpText = "SyncPlayableRect(region)";
  constexpr const char* kCurrentTimeHelpText =
    "Get the current time in seconds, counting from 0 at application start. This is wall-clock time and is unaffected by gameplay.";
  constexpr const char* kGameTimeUserHelpText =
    "Get the current game time in seconds. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGameTickUserHelpText =
    "Get the current game time in ticks. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kIsAllyUserHelpText = "IsAlly(army1,army2)";
  constexpr const char* kIsEnemyUserHelpText = "IsEnemy(army1,army2)";
  constexpr const char* kIsNeutralUserHelpText = "IsNeutral(army1,army2)";
  constexpr const char* kParseEntityCategoryUserHelpText = "parse a string to generate a new entity category";
  constexpr const char* kParseEntityCategoryUserNoSessionText = "ParseEntityCategory: no session loaded";
  constexpr const char* kHasLocalizedVOUserHelpText = "HasLocalizedVO(languageCode)";
  constexpr const char* kCheatsEnabledHelpText =
    "Return true iff cheats are enabled.  Logs the cheat attempt no matter what.";
  constexpr const char* kGetCurrentCommandSourceHelpText = "Return the (1 based) index of the current command source.";
  constexpr const char* kGetEntitiesInRectHelpText = "Return the enitities inside the given rectangle";
  constexpr const char* kGetUnitsInRectHelpText = "Return the units inside the given rectangle";
  constexpr const char* kGetReclaimablesInRectHelpText = "Return the reclamable things inside the given rectangle";
  constexpr const char* kGetMapSizeHelpText = "sizeX, sizeZ = GetMapSize()";
  constexpr const char* kGetFocusArmySimHelpText = "GetFocusArmy()";
  constexpr const char* kAudioSetLanguageUserHelpText = "AudioSetLanguage(name)";
  constexpr const char* kAudioSetLanguageSimHelpText = "AudioSetLanguage(name)";
  constexpr const char* kHasLocalizedVOSimHelpText = "HasLocalizedVO(language)";
  constexpr const char* kSubmitXMLArmyStatsHelpText = "Request that we submit xml army stats to gpg.net.";
  constexpr const char* kSetInvertMidMouseButtonHelpText = "SetInvertMidMouseButton";
  constexpr const char* kShouldCreateInitialArmyUnitsHelpText = "";
  constexpr const char* kListArmiesHelpText = "";
  constexpr const char* kGetArmyBrainHelpText = "army";
  constexpr const char* kSetArmyStartHelpText = "army, x, z";
  constexpr const char* kGenerateArmyStartHelpText = "army";
  constexpr const char* kArmyInitializePrebuiltUnitsHelpText = "army";
  constexpr const char* kSetIgnoreArmyUnitCapHelpText = "army, flag";
  constexpr const char* kSetIgnorePlayableRectHelpText = "army, flag";
  constexpr const char* kIsAllySimHelpText = "IsAlly(army1,army2)";
  constexpr const char* kIsEnemySimHelpText = "IsEnemy(army1,army2)";
  constexpr const char* kIsNeutralSimHelpText = "IsNeutral(army1,army2)";
  constexpr const char* kArmyIsCivilianHelpText = "ArmyIsCivilian(army)";
  constexpr const char* kSetArmyFactionIndexHelpText = "SetArmyFactionIndex(army,index)";
  constexpr const char* kOkayToMessWithArmyHelpText =
    "Return true if the current command source is authorized to mess with the given army.  Or if cheats are enabled.";
  constexpr const char* kArmyIsOutOfGameHelpText =
    "ArmyIsOutOfGame(army) -- return true iff the indicated army has been defeated.";
  constexpr const char* kSetArmyOutOfGameHelpText =
    "SetArmyOutOfGame(army) -- indicate that the supplied army has been defeated.";
  constexpr const char* kArmyGetHandicapHelpText = "army";
  constexpr const char* kSetArmyEconomyHelpText = "army, mass, energy";
  constexpr const char* kGetArmyUnitCostTotalHelpText = "army";
  constexpr const char* kGetArmyUnitCapHelpText = "army";
  constexpr const char* kSetArmyUnitCapHelpText = "army, unitCap";
  constexpr const char* kSetArmyAIPersonalityHelpText = "SetArmyAIPersonality(army,personality)";
  constexpr const char* kSetArmyShowScoreHelpText =
    "SetArmyColor(army, bool) - determines if the user should be able to see the army score";
  constexpr const char* kSetArmyStatsSyncArmyHelpText = "Set the army index for which to sync army stats (-1 for none)";
  constexpr const char* kInitializeArmyAIHelpText = "army";
  constexpr const char* kSetArmyPlansHelpText = "army, plans";
  constexpr const char* kSetArmyColorHelpText = "SetArmyColor(army,r,g,b)";
  constexpr const char* kSetAlliedVictoryHelpText = "SetAlliedVictory(army,bool)";
  constexpr const char* kSetAllianceHelpText = "SetAlliance(army1,army2,<Neutral|Enemy|Ally>";
  constexpr const char* kSetAllianceOneWayHelpText = "SetAllianceOneWay(army1,army2,<Neutral|Enemy|Ally>";
  constexpr const char* kGetEntityByIdHelpText = "Get entity by entity id";
  constexpr const char* kGetUnitByIdSimHelpText = "Get entity by entity id";
  constexpr const char* kGetUnitByIdUserHelpText = "GetUnitById(id)";
  constexpr const char* kGetTerrainHeightHelpText = "type = GetTerrainHeight(x,z)";
  constexpr const char* kGetSurfaceHeightHelpText = "type = GetSurfaceHeight(x,z)";
  constexpr const char* kGetTerrainTypeOffsetHelpText = "type = GetTerrainTypeOffset(x,z)";
  constexpr const char* kGetTerrainTypeLuaDefHelpText = "type = GetTerrainType(x,z)";
  constexpr const char* kSetTerrainTypeLuaDefHelpText = "SetTerrainType(x,z,type)";
  constexpr const char* kSetTerrainTypeRectLuaDefHelpText = "SetTerrainType(rect,type)";
  constexpr const char* kGetTerrainTypeHelpText = "GetTerrainType( x, z )";
  constexpr const char* kSetTerrainTypeHelpText = "SetTerrainType( x, z, terrainTypeTable )";
  constexpr const char* kSetTerrainTypeRectHelpText = "SetTerrainTypeRect( rect, terrainTypeTable )";
  constexpr const char* kSetPlayableRectHelpText = "SetPlayableRect( minX, minZ, maxX, maxZ )";
  constexpr const char* kWarpHelpText = "Warp( unit, location, [orientation] )";
  constexpr const char* kChangeUnitArmyHelpText = "ChangeUnitArmy(unit,armyIndex) Change a unit's army";
  constexpr const char* kGetUnitBlueprintByNameLuaDefHelpText = "blueprint = GetUnitBlueprintByName(bpName)";
  constexpr const char* kGetUnitBlueprintByNameHelpText = "GetUnitBlueprintByName(blueprint_name)";
  constexpr const char* kGenerateRandomOrientationHelpText = "rotation = GenerateRandomOrientation()";
  constexpr const char* kDrawLineHelpText = "Draw a 3d line from a to b with color c";
  constexpr const char* kDrawLinePopHelpText =
    "Draw a 3d line from a to b with color c with a circle at the end of the target line";
  constexpr const char* kDrawCircleHelpText = "Draw a 3d circle at a with size s and color c";
  constexpr const char* kPlayLoopHelpText = "handle = PlayLoop(self,sndParams)";
  constexpr const char* kStopLoopHelpText = "StopLoop(self,handle)";
  constexpr const char* kSetAutoModeHelpText = "See if anyone in the list is auto building";
  constexpr const char* kSetAutoSurfaceModeHelpText = "See if anyone in the list is auto surfacing";
  constexpr const char* kToggleScriptBitExpectedArgsText = "ToggleScriptBit(units, bit, curState)";
  constexpr const char* kToggleScriptBitHelpText = "Set the right fire state for the units passed in";
  constexpr const char* kSetPausedHelpText = "Pause builders in this list";
  constexpr const char* kValidateUnitsListHelpText = "Validate a list of units ";
  constexpr const char* kSpecFootprintsHelpText = "SpecFootprints { spec } -- define the footprint types for pathfinding";
  constexpr const char* kRegisterUnitBlueprintHelpText = "UnitBlueprint { spec } - define a type of unit";
  constexpr const char* kRegisterPropBlueprintHelpText = "PropBlueprint { spec } - define a type of prop";
  constexpr const char* kRegisterProjectileBlueprintHelpText =
    "ProjectileBlueprint { spec } - define a type of projectile";
  constexpr const char* kRegisterMeshBlueprintHelpText = "MeshBlueprint { spec } - define mesh properties";
  constexpr const char* kRegisterTrailEmitterBlueprintHelpText =
    "TrailEmitterBlueprint { spec } - define a polytrail emitter";
  constexpr const char* kRegisterEmitterBlueprintHelpText = "EmitterBlueprint { spec } - define a particle emitter";
  constexpr const char* kRegisterBeamBlueprintHelpText = "BeamBlueprint { spec } - define a beam effect";
  constexpr const char* kBlueprintLoaderUpdateProgressHelpText = "";
  constexpr const char* kFormatTimeHelpText =
    "string FormatTime(seconds) - format a string displaying the time specified in seconds";
  constexpr const char* kGetGameTimeHelpText =
    "string GetGameTime() - returns a formatted string displaying the time the game has been played";
  constexpr const char* kGetSystemTimeHelpText =
    "string GetSystemTime() - returns a formatted string displaying the System time";
  constexpr const char* kRemoveProfileDirectoriesHelpText =
    "RemoveProfileDirectories(string profile) - Removes the profile directory and all special files";
  constexpr const char* kCopyCurrentReplayHelpText =
    "CopyCurrentReplay(string profile, string newFilename) - copy the current replay to another file";
  constexpr const char* kSetOverlayFiltersHelpText = "SetOverlayFilters(list)";
  constexpr const char* kGenerateBuildTemplateFromSelectionHelpText =
    "generate and enable build templates from the current selection.";
  constexpr const char* kClearBuildTemplatesHelpText = "clear and disable the build templates.";
  constexpr const char* kRenderOverlayMilitaryHelpText = "RenderOverlayMilitary(bool)";
  constexpr const char* kRenderOverlayIntelHelpText = "RenderOverlayIntel(bool)";
  constexpr const char* kRenderOverlayEconomyHelpText = "RenderOverlayEconomy(bool)";
  constexpr const char* kTeamColorModeHelpText = "TeamColorMode(bool)";
  constexpr const char* kEjectSessionClientHelpText =
    "EjectSessionClient(int clientIndex) -- eject another client from your session";
  constexpr const char* kNoSessionStartedText = "No session started.";
  constexpr const char* kNoActiveSessionPeriodText = "No active session.";
  constexpr const char* kUiLayerNotInitializedText = "UI layer has not been initialized.";
  constexpr const char* kNoActiveSessionText = "No active session";
  constexpr const char* kEntityCategoryCountHelpText = "Count how many units fit the specified category";
  constexpr const char* kEntityCategoryContainsUserHelpText = "See if a unit category contains this unit";
  constexpr const char* kEntityCategoryContainsUserNoSessionText = "EntityCategoryContains: no session loaded";
  constexpr const char* kEntityCategoryCountInvalidTableText =
    "Pass in invalid table of units to EntityCategoryFilterDown!!.";
  constexpr const char* kEntityCategoryFilterDownUserHelpText =
    "Filter a list of units to only those found in the category";
  constexpr const char* kEntityCategoryFilterDownUserNoSessionText = "EntityCategoryFilterDown: no session loaded";
  constexpr const char* kEntityCategoryFilterDownUserInvalidCategoryText =
    "EntityCategoryFilterDown: expected an entity category object";
  constexpr const char* kEntityCategoryFilterOutHelpText =
    "Filter a list of units to exclude those found in the category";
  constexpr const char* kEntityCategoryFilterOutNoSessionText = "EntityCategoryFilterOut: no session loaded";
  constexpr const char* kEntityCategoryFilterOutInvalidCategoryText =
    "EntityCategoryFilterOut: expected an entity category object";
  constexpr const char* kSetArmyColorSyntaxText = "syntax: SetArmyColor(army,r,g,b)";
  constexpr const char* kSetArmyColorInvalidArmyText = "Invalid army %i";
  constexpr const char* kDbgUsageText = "usage: %s [name]";

  /// 0x00E352F4, pushed to Sim::Printf when fewer than five tokens are given.
  constexpr const char* kDebugSetPlayableRectUsageText = "usage: DebugSetPlayableRect x0 y0 x1 y1";
  /// 0x00E35114, pushed to Sim::Printf when `STIMap::SetPlayableMapRect` refuses the rect.
  constexpr const char* kDebugSetPlayableRectInvalidText = "Attempted to set an invalid playable rect.";
  /// 0x00E3531C, the Sim-Lua mirror `gpg::STR_Printf` builds at 0x0075D739.
  constexpr const char* kDebugSetPlayableRectSyncFormat = "SyncPlayableRect({ x0=%s, x1=%s, y0=%s, y1=%s })";

  /// 0x0064BEC7, pushed to Sim::Printf when the amount argument is missing.
  constexpr const char* kDamageUnitUsageText = "Syntax: DamageUnit <amount>";
  /// 0x0064BE2D ("Debug"), the damage type DamageUnit reports.
  constexpr const char* kDamageUnitDamageType = "Debug";
  constexpr const char* kDbgAvailableOverlaysText = "Available overlays";
  constexpr const char* kDbgUnknownOverlayText = "Unknown debug overlay: %s";
  constexpr const char* kDbgAmbiguousOverlayText = "Ambiguous debug overlay: %s.";
  constexpr const char* kDbgCouldBeAnyOfText = "Could be any of:";
  constexpr const char* kUnknownArmyMessage = "Unknown army: %s";
  constexpr const char* kUnexpectedArmyTypeMessage = "Unexpected type for army object";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaInvalidBoolWarning = "%s\n  invalid argument %d, use as boolean";
  constexpr std::uint32_t kIntelRadiusMagnitudeMask = 0x7FFFFFFFu;
  constexpr std::uint32_t kIntelEnabledFlagMask = ~kIntelRadiusMagnitudeMask;
  constexpr std::size_t kEntityIntelAttributesOffset = 0x128u;
  constexpr std::size_t kDiscardClientSlotCount = 17u;
  constexpr std::uintptr_t kLuaCallbackDispatchBlockedFlagEa = 0x011FD23Fu;

  struct EntityIntelAttributeRangesView
  {
    std::uint32_t vision;       // +0x00
    std::uint32_t waterVision;  // +0x04
    std::uint32_t radar;        // +0x08
    std::uint32_t sonar;        // +0x0C
    std::uint32_t omni;         // +0x10
    std::uint32_t radarStealth; // +0x14
    std::uint32_t sonarStealth; // +0x18
    std::uint32_t cloak;        // +0x1C
  };

  static_assert(sizeof(EntityIntelAttributeRangesView) == 0x20, "EntityIntelAttributeRangesView size must be 0x20");
  static_assert(
    offsetof(EntityIntelAttributeRangesView, vision) == 0x00, "EntityIntelAttributeRangesView::vision offset must be 0x00"
  );
  static_assert(
    offsetof(EntityIntelAttributeRangesView, cloak) == 0x1C, "EntityIntelAttributeRangesView::cloak offset must be 0x1C"
  );

  [[nodiscard]] const EntityIntelAttributeRangesView& GetEntityIntelAttributeRanges(const moho::Entity& entity) noexcept
  {
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(&entity);
    const auto* const ranges = reinterpret_cast<const EntityIntelAttributeRangesView*>(bytes + kEntityIntelAttributesOffset);
    return *ranges;
  }

  [[nodiscard]] EntityIntelAttributeRangesView& GetEntityIntelAttributeRangesMutable(moho::Entity& entity) noexcept
  {
    auto* const bytes = reinterpret_cast<std::uint8_t*>(&entity);
    auto* const ranges = reinterpret_cast<EntityIntelAttributeRangesView*>(bytes + kEntityIntelAttributesOffset);
    return *ranges;
  }

  void SetIntelEnabledBit(std::uint32_t& lane, const bool enabled) noexcept
  {
    if (enabled) {
      lane |= kIntelEnabledFlagMask;
    } else {
      lane &= kIntelRadiusMagnitudeMask;
    }
  }

  void SetEntityAttributeRangePreserveEnabledBit(
    EntityIntelAttributeRangesView& ranges, const std::int32_t attributeLane, const std::uint32_t radius
  ) noexcept
  {
    const auto setLane = [radius](std::uint32_t& lane) {
      lane = (lane & kIntelEnabledFlagMask) | (radius & kIntelRadiusMagnitudeMask);
    };

    switch (attributeLane) {
    case 0:
      setLane(ranges.vision);
      return;
    case 1:
      setLane(ranges.waterVision);
      return;
    case 2:
      setLane(ranges.radar);
      return;
    case 3:
      setLane(ranges.sonar);
      return;
    case 4:
      setLane(ranges.omni);
      return;
    case 10:
      setLane(ranges.cloak);
      return;
    case 11:
      setLane(ranges.radarStealth);
      return;
    case 12:
      setLane(ranges.sonarStealth);
      return;
    default:
      return;
    }
  }

  void SetEntityIntelEnabledAttributeBit(moho::Entity& entity, const moho::EIntel intelType, const bool enabled) noexcept
  {
    EntityIntelAttributeRangesView& ranges = GetEntityIntelAttributeRangesMutable(entity);
    switch (intelType) {
    case moho::INTEL_Vision:
      SetIntelEnabledBit(ranges.vision, enabled);
      return;
    case moho::INTEL_WaterVision:
      SetIntelEnabledBit(ranges.waterVision, enabled);
      return;
    case moho::INTEL_Radar:
      SetIntelEnabledBit(ranges.radar, enabled);
      return;
    case moho::INTEL_Sonar:
      SetIntelEnabledBit(ranges.sonar, enabled);
      return;
    case moho::INTEL_Omni:
      SetIntelEnabledBit(ranges.omni, enabled);
      return;
    case moho::INTEL_Cloak:
      SetIntelEnabledBit(ranges.cloak, enabled);
      return;
    case moho::INTEL_RadarStealth:
      SetIntelEnabledBit(ranges.radarStealth, enabled);
      return;
    case moho::INTEL_SonarStealth:
      SetIntelEnabledBit(ranges.sonarStealth, enabled);
      return;
    default:
      return;
    }
  }

  [[nodiscard]] std::uint32_t GetEntityAttributeRangeMagnitude(
    const EntityIntelAttributeRangesView& ranges, const std::int32_t attributeLane
  ) noexcept
  {
    switch (attributeLane) {
    case 0:
      return ranges.vision & kIntelRadiusMagnitudeMask;
    case 1:
      return ranges.waterVision & kIntelRadiusMagnitudeMask;
    case 2:
      return ranges.radar & kIntelRadiusMagnitudeMask;
    case 3:
      return ranges.sonar & kIntelRadiusMagnitudeMask;
    case 4:
      return ranges.omni & kIntelRadiusMagnitudeMask;
    case 10:
      return ranges.cloak & kIntelRadiusMagnitudeMask;
    case 11:
      return ranges.radarStealth & kIntelRadiusMagnitudeMask;
    case 12:
      return ranges.sonarStealth & kIntelRadiusMagnitudeMask;
    default:
      return 0u;
    }
  }

  [[nodiscard]] gpg::RRef MakeEAllianceRef(moho::EAlliance* const allianceType)
  {
    gpg::RRef enumRef{};
    if (allianceType == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEAllianceType = nullptr;
    if (sEAllianceType == nullptr) {
      sEAllianceType = gpg::LookupRType(typeid(moho::EAlliance));
    }

    enumRef.mObj = allianceType;
    enumRef.mType = sEAllianceType;
    return enumRef;
  }

  [[nodiscard]] gpg::RRef MakeEIntelRef(moho::EIntel* const intelType)
  {
    gpg::RRef enumRef{};
    if (intelType == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEIntelType = nullptr;
    if (sEIntelType == nullptr) {
      sEIntelType = gpg::LookupRType(typeid(moho::EIntel));
    }

    enumRef.mObj = intelType;
    enumRef.mType = sEIntelType;
    return enumRef;
  }

  [[nodiscard]] moho::CIntelPosHandle* ResolveIntelPosHandleForType(
    moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    const int intelIndex = static_cast<int>(intelType);
    if (intelIndex < 0 || intelIndex >= static_cast<int>(moho::INTEL_Jammer)) {
      return nullptr;
    }
    if (intelIndex >= static_cast<int>(moho::CIntel::kHandleCount)) {
      return nullptr;
    }

    return intelManager.mIntelHandles[static_cast<std::size_t>(intelIndex)];
  }

  [[nodiscard]] const moho::CIntelPosHandle* ResolveIntelPosHandleForType(
    const moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    const int intelIndex = static_cast<int>(intelType);
    if (intelIndex < 0 || intelIndex >= static_cast<int>(moho::INTEL_Jammer)) {
      return nullptr;
    }
    if (intelIndex >= static_cast<int>(moho::CIntel::kHandleCount)) {
      return nullptr;
    }

    return intelManager.mIntelHandles[static_cast<std::size_t>(intelIndex)];
  }

  [[nodiscard]] moho::CIntelToggleState* ResolveIntelToggleStateForType(
    moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    const std::array<moho::CIntelToggleState*, 5> toggleLanes = {
      &intelManager.mJamming,
      &intelManager.mCloak,
      &intelManager.mSpoof,
      &intelManager.mSonarStealth,
      &intelManager.mRadarStealth,
    };

    const int toggleIndex = static_cast<int>(intelType) - static_cast<int>(moho::INTEL_Jammer);
    if (toggleIndex < 0 || toggleIndex >= static_cast<int>(toggleLanes.size())) {
      return nullptr;
    }

    return toggleLanes[static_cast<std::size_t>(toggleIndex)];
  }

  [[nodiscard]] const moho::CIntelToggleState* ResolveIntelToggleStateForType(
    const moho::CIntel& intelManager, const moho::EIntel intelType
  ) noexcept
  {
    const std::array<const moho::CIntelToggleState*, 5> toggleLanes = {
      &intelManager.mJamming,
      &intelManager.mCloak,
      &intelManager.mSpoof,
      &intelManager.mSonarStealth,
      &intelManager.mRadarStealth,
    };

    const int toggleIndex = static_cast<int>(intelType) - static_cast<int>(moho::INTEL_Jammer);
    if (toggleIndex < 0 || toggleIndex >= static_cast<int>(toggleLanes.size())) {
      return nullptr;
    }

    return toggleLanes[static_cast<std::size_t>(toggleIndex)];
  }

  void RequeueEntityCoordUpdate(moho::Entity& entity) noexcept
  {
    entity.mCoordNode.ListLinkAfter(&entity.SimulationRef->mCoordEntities);
  }

  [[nodiscard]] bool IsIntelEnabledForType(const moho::CIntel& intelManager, const moho::EIntel intelType) noexcept
  {
    if (const auto* const handle = ResolveIntelPosHandleForType(intelManager, intelType); handle != nullptr) {
      return handle->mEnabled != 0u;
    }

    const moho::CIntelToggleState* const toggleState = ResolveIntelToggleStateForType(intelManager, intelType);
    if (toggleState == nullptr) {
      return false;
    }
    return toggleState->present != 0u && toggleState->enabled != 0u;
  }

  [[nodiscard]] gpg::RType* CachedERuleBPUnitCommandCapsType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(moho::ERuleBPUnitCommandCaps));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedEUnitCommandTypeType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return sType;
  }

  struct DiscardPatchState
  {
    std::array<const void*, kDiscardClientSlotCount> clientPointers{};
    std::uint32_t currentClientCount = 0;
    std::uint32_t didDiscard = 0;
  };

  DiscardPatchState gDiscardPatchState{};

  template <std::size_t N>
  [[nodiscard]] bool ContainsPointer(
    const std::array<const void*, N>& candidates,
    const std::size_t count,
    const void* const value
  ) noexcept
  {
    const std::size_t boundedCount = std::min(count, N);
    for (std::size_t index = 0; index < boundedCount; ++index) {
      if (candidates[index] == value) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] std::size_t ResolveDiscardScanCount(const std::uint32_t currentClientCount) noexcept
  {
    if (currentClientCount <= 1u || currentClientCount > kDiscardClientSlotCount) {
      return kDiscardClientSlotCount;
    }
    return static_cast<std::size_t>(currentClientCount - 1u);
  }

  [[nodiscard]] bool IsLuaCallbackDispatchBlocked() noexcept
  {
#if defined(_M_IX86)
    const auto* const blockedFlag =
      reinterpret_cast<const volatile std::uint8_t*>(kLuaCallbackDispatchBlockedFlagEa);
    return *blockedFlag == 1u;
#else
    return false;
#endif
  }

  [[nodiscard]] Sim* ResolveGlobalSim(lua_State* const luaContext) noexcept
  {
    if (!luaContext || !luaContext->l_G) {
      return nullptr;
    }
    return luaContext->l_G->globalUserData;
  }

  [[nodiscard]] bool ParseRectFromLuaArguments(
    LuaPlus::LuaState* const state,
    const char* const helpText,
    gpg::Rect2f& outRect
  )
  {
    if (!state || !state->m_state) {
      return false;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", helpText, 1, 4, argumentCount);
    }

    if (argumentCount == 1) {
      const LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
      outRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
      return true;
    }

    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      x0Arg.TypeError("number");
    }
    outRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      z0Arg.TypeError("number");
    }
    outRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      x1Arg.TypeError("number");
    }
    outRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      z1Arg.TypeError("number");
    }
    outRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
    return true;
  }

  [[nodiscard]] bool IsEntityPositionInsideRect(const Entity* const entity, const gpg::Rect2f& rect) noexcept
  {
    if (entity == nullptr) {
      return false;
    }

    const Wm3::Vec3f& position = entity->GetPositionWm3();
    return rect.Contains(position.x, position.z);
  }

  /**
   * Address: 0x0074B550 (FUN_0074B550)
   *
   * What it does:
   * Receives one concatenated print line from `SCR_ConcatArgsAndCall` and
   * forwards it into the active sim log lane.
   */
  void PrintSimConcatSink(LuaPlus::LuaState* const state, const char* const text)
  {
    if (!state || !state->m_state) {
      return;
    }

    if (Sim* const sim = ResolveGlobalSim(state->m_state); sim != nullptr) {
      sim->Printf("%s", text != nullptr ? text : "");
    }
  }

  [[nodiscard]] RRuleGameRulesImpl* ResolveRulesImpl(LuaPlus::LuaState* const state) noexcept
  {
    if (!state || !state->m_state) {
      return nullptr;
    }

    Sim* const sim = ResolveGlobalSim(state->m_state);
    if (!sim || !sim->mRules) {
      return nullptr;
    }

    return static_cast<RRuleGameRulesImpl*>(sim->mRules);
  }

  /**
   * Address: 0x005794A0 (FUN_005794A0)
   *
   * What it does:
   * Returns the `Sim::mRules` pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] RRuleGameRules* ReadSimRulesLane(Sim* const sim) noexcept
  {
    return sim != nullptr ? sim->mRules : nullptr;
  }

  /**
   * Address: 0x005794B0 (FUN_005794B0)
   *
   * What it does:
   * Returns the `Sim::mMapData` pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] STIMap* ReadSimMapDataLane(Sim* const sim) noexcept
  {
    return sim != nullptr ? sim->mMapData : nullptr;
  }

  [[nodiscard]] bool HasNamedFootprint(
    const SRuleFootprintsBlueprint& footprintTable,
    const msvc8::string& footprintName
  ) noexcept
  {
    const SRuleFootprintNode* const sentinel = footprintTable.mHead;
    if (!sentinel) {
      return false;
    }

    for (const SRuleFootprintNode* node = sentinel->next; node && node != sentinel; node = node->next) {
      if (node->value.mName == footprintName) {
        return true;
      }
    }

    return false;
  }

  void AppendNamedFootprint(SRuleFootprintsBlueprint& footprintTable, const SNamedFootprint& footprint)
  {
    SRuleFootprintNode* const sentinel = footprintTable.mHead;
    if (!sentinel) {
      return;
    }

    SRuleFootprintNode* const tail = sentinel->prev ? sentinel->prev : sentinel;
    auto* const node = new SRuleFootprintNode{};
    node->value = footprint;
    node->next = sentinel;
    node->prev = tail;

    tail->next = node;
    sentinel->prev = node;
    ++footprintTable.mSize;
  }

  [[nodiscard]] CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }

  [[nodiscard]] CScrLuaInitFormSet& CoreLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Core"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("Core");
    return fallbackSet;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  /**
   * Address: 0x008ADF40 (FUN_008ADF40, func_GetVoiceDir)
   *
   * What it does:
   * Checks whether `/sounds/voice/<language>` exists in the mounted virtual
   * file-system lane.
   */
  [[nodiscard]] bool HasLocalizedVoiceDirectory(const msvc8::string& language)
  {
    const msvc8::string voiceDirectory = gpg::STR_Printf("/sounds/voice/%s", language.c_str());
    return FILE_GetFileInfo(voiceDirectory.c_str(), nullptr, false);
  }

  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const unit) noexcept
  {
    return unit ? static_cast<IUnit*>(unit) : nullptr;
  }

  [[nodiscard]] const IUnit* ResolveIUnitBridge(const UserUnit* const unit) noexcept
  {
    return unit ? static_cast<const IUnit*>(unit) : nullptr;
  }

  struct UserEntityWeakRefRuntimeView
  {
    void* ownerLinkSlot;                          // +0x00
    UserEntityWeakRefRuntimeView* nextOwnerLink;  // +0x04
  };
  static_assert(sizeof(UserEntityWeakRefRuntimeView) == 0x08, "UserEntityWeakRefRuntimeView size must be 0x08");
  static_assert(
    offsetof(UserEntityWeakRefRuntimeView, ownerLinkSlot) == 0x00,
    "UserEntityWeakRefRuntimeView::ownerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(UserEntityWeakRefRuntimeView, nextOwnerLink) == 0x04,
    "UserEntityWeakRefRuntimeView::nextOwnerLink offset must be 0x04"
  );

  struct UserEntityWeakSetNodeRuntimeView
  {
    UserEntityWeakSetNodeRuntimeView* left;        // +0x00
    UserEntityWeakSetNodeRuntimeView* parent;      // +0x04
    UserEntityWeakSetNodeRuntimeView* right;       // +0x08
    std::uint32_t key;                             // +0x0C
    UserEntityWeakRefRuntimeView weakEntityLink;   // +0x10
    std::uint8_t color;                            // +0x18
    std::uint8_t isNil;                            // +0x19
    std::uint8_t pad_001A_001B[0x02];
  };
  static_assert(sizeof(UserEntityWeakSetNodeRuntimeView) == 0x1C, "UserEntityWeakSetNodeRuntimeView size must be 0x1C");
  static_assert(
    offsetof(UserEntityWeakSetNodeRuntimeView, weakEntityLink) == 0x10,
    "UserEntityWeakSetNodeRuntimeView::weakEntityLink offset must be 0x10"
  );
  static_assert(
    offsetof(UserEntityWeakSetNodeRuntimeView, isNil) == 0x19,
    "UserEntityWeakSetNodeRuntimeView::isNil offset must be 0x19"
  );

  struct UserEntityWeakSetRuntimeView
  {
    void* allocatorProxy;                           // +0x00
    UserEntityWeakSetNodeRuntimeView* head;         // +0x04
    std::uint32_t size;                             // +0x08
  };
  static_assert(sizeof(UserEntityWeakSetRuntimeView) == 0x0C, "UserEntityWeakSetRuntimeView size must be 0x0C");
  static_assert(
    offsetof(UserEntityWeakSetRuntimeView, head) == 0x04,
    "UserEntityWeakSetRuntimeView::head offset must be 0x04"
  );
  static_assert(
    offsetof(UserEntityWeakSetRuntimeView, size) == 0x08,
    "UserEntityWeakSetRuntimeView::size offset must be 0x08"
  );

  struct UserArmyAvatarVectorRuntimeView
  {
    void* allocatorProxy;                            // +0x00
    UserEntityWeakRefRuntimeView* begin;             // +0x04
    UserEntityWeakRefRuntimeView* end;               // +0x08
    UserEntityWeakRefRuntimeView* capacityEnd;       // +0x0C
  };
  static_assert(sizeof(UserArmyAvatarVectorRuntimeView) == 0x10, "UserArmyAvatarVectorRuntimeView size must be 0x10");
  static_assert(
    offsetof(UserArmyAvatarVectorRuntimeView, begin) == 0x04,
    "UserArmyAvatarVectorRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(UserArmyAvatarVectorRuntimeView, end) == 0x08, "UserArmyAvatarVectorRuntimeView::end offset must be 0x08"
  );

  struct UserArmyAvatarRuntimeView
  {
    std::uint8_t pad_0000_01E8[0x1E8];
    UserArmyAvatarVectorRuntimeView avatarWeakRefs;  // +0x1E8
  };
  static_assert(
    offsetof(UserArmyAvatarRuntimeView, avatarWeakRefs) == 0x1E8,
    "UserArmyAvatarRuntimeView::avatarWeakRefs offset must be 0x1E8"
  );

  struct UserArmyIdleSetsRuntimeView
  {
    std::uint8_t pad_0000_01F8[0x1F8];
    UserEntityWeakSetRuntimeView idleEngineerUnits;  // +0x1F8
    UserEntityWeakSetRuntimeView idleFactoryUnits;   // +0x204
  };
  static_assert(
    offsetof(UserArmyIdleSetsRuntimeView, idleEngineerUnits) == 0x1F8,
    "UserArmyIdleSetsRuntimeView::idleEngineerUnits offset must be 0x1F8"
  );
  static_assert(
    offsetof(UserArmyIdleSetsRuntimeView, idleFactoryUnits) == 0x204,
    "UserArmyIdleSetsRuntimeView::idleFactoryUnits offset must be 0x204"
  );

  [[nodiscard]] UserArmy* ResolveFocusArmy(CWldSession* const session) noexcept
  {
    if (session == nullptr || session->FocusArmy < 0) {
      return nullptr;
    }

    const std::size_t focusArmyIndex = static_cast<std::size_t>(session->FocusArmy);
    if (focusArmyIndex >= session->userArmies.size()) {
      return nullptr;
    }

    return session->userArmies[focusArmyIndex];
  }

  [[nodiscard]] UserEntity* DecodeLinkedUserEntity(const UserEntityWeakRefRuntimeView& weakRef) noexcept
  {
    if (weakRef.ownerLinkSlot == nullptr) {
      return nullptr;
    }

    constexpr std::uintptr_t kOwnerLinkOffset = offsetof(UserEntity, mIUnitChainHead);
    const std::uintptr_t rawOwnerLink = reinterpret_cast<std::uintptr_t>(weakRef.ownerLinkSlot);
    if (rawOwnerLink <= kOwnerLinkOffset) {
      return nullptr;
    }

    return reinterpret_cast<UserEntity*>(rawOwnerLink - kOwnerLinkOffset);
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetMinNode(
    UserEntityWeakSetNodeRuntimeView* node,
    UserEntityWeakSetNodeRuntimeView* const head
  ) noexcept
  {
    while (node != nullptr && node != head && node->left != head) {
      node = node->left;
    }
    return node != nullptr ? node : head;
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetFirstNode(const UserEntityWeakSetRuntimeView& set) noexcept
  {
    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    if (head == nullptr || head->isNil == 0u) {
      return nullptr;
    }

    UserEntityWeakSetNodeRuntimeView* const root = head->parent;
    if (root == nullptr || root == head || root->isNil != 0u) {
      return head;
    }

    return WeakSetMinNode(root, head);
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetNextNode(
    UserEntityWeakSetNodeRuntimeView* node,
    UserEntityWeakSetNodeRuntimeView* const head
  ) noexcept
  {
    if (node == nullptr || head == nullptr || node == head) {
      return head;
    }

    if (node->right != head) {
      return WeakSetMinNode(node->right, head);
    }

    UserEntityWeakSetNodeRuntimeView* parent = node->parent;
    while (parent != nullptr && parent != head && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    return parent != nullptr ? parent : head;
  }

  [[nodiscard]] bool WeakSetNodeHasLiveOwner(const UserEntityWeakSetNodeRuntimeView* const node) noexcept
  {
    return node != nullptr
      && node->isNil == 0u
      && node->weakEntityLink.ownerLinkSlot != nullptr
      && node->weakEntityLink.ownerLinkSlot != reinterpret_cast<void*>(8);
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetTreeMaxNode(
    UserEntityWeakSetNodeRuntimeView* node,
    UserEntityWeakSetNodeRuntimeView* const head
  ) noexcept
  {
    while (node != nullptr && node != head && node->right != head) {
      node = node->right;
    }
    return node != nullptr ? node : head;
  }

  void WeakSetRecomputeExtrema(UserEntityWeakSetRuntimeView& set) noexcept
  {
    if (set.head == nullptr) {
      return;
    }

    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    UserEntityWeakSetNodeRuntimeView* const root = head->parent;
    if (root == nullptr || root == head || root->isNil != 0u) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    head->left = WeakSetMinNode(root, head);
    head->right = WeakSetTreeMaxNode(root, head);
  }

  void WeakSetReplaceSubtree(
    UserEntityWeakSetRuntimeView& set,
    UserEntityWeakSetNodeRuntimeView* const oldNode,
    UserEntityWeakSetNodeRuntimeView* const newNode
  ) noexcept
  {
    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    if (oldNode->parent == head) {
      head->parent = newNode;
    } else if (oldNode == oldNode->parent->left) {
      oldNode->parent->left = newNode;
    } else {
      oldNode->parent->right = newNode;
    }

    if (newNode != nullptr && newNode->isNil == 0u) {
      newNode->parent = oldNode->parent;
    }
  }

  void WeakSetRotateLeft(UserEntityWeakSetRuntimeView& set, UserEntityWeakSetNodeRuntimeView* const node) noexcept
  {
    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    UserEntityWeakSetNodeRuntimeView* const pivot = node->right;
    node->right = pivot->left;
    if (pivot->left != nullptr && pivot->left->isNil == 0u) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void WeakSetRotateRight(UserEntityWeakSetRuntimeView& set, UserEntityWeakSetNodeRuntimeView* const node) noexcept
  {
    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    UserEntityWeakSetNodeRuntimeView* const pivot = node->left;
    node->left = pivot->right;
    if (pivot->right != nullptr && pivot->right->isNil == 0u) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void WeakSetUnlinkOwnerRef(UserEntityWeakRefRuntimeView& weakRef) noexcept
  {
    auto** ownerLinkSlot = reinterpret_cast<UserEntityWeakRefRuntimeView**>(weakRef.ownerLinkSlot);
    if (ownerLinkSlot == nullptr) {
      return;
    }

    while (*ownerLinkSlot != nullptr && *ownerLinkSlot != &weakRef) {
      ownerLinkSlot = &(*ownerLinkSlot)->nextOwnerLink;
    }

    if (*ownerLinkSlot == &weakRef) {
      *ownerLinkSlot = weakRef.nextOwnerLink;
    }

    weakRef.ownerLinkSlot = nullptr;
    weakRef.nextOwnerLink = nullptr;
  }

  void WeakSetFixupAfterErase(
    UserEntityWeakSetRuntimeView& set,
    UserEntityWeakSetNodeRuntimeView* node,
    UserEntityWeakSetNodeRuntimeView* nodeParent
  ) noexcept
  {
    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    UserEntityWeakSetNodeRuntimeView* parent = node != nullptr && node->isNil == 0u ? node->parent : nodeParent;
    while (node != head->parent && (node == nullptr || node->isNil != 0u || node->color == 1u)) {
      if (parent == nullptr) {
        break;
      }

      if (node == parent->left) {
        UserEntityWeakSetNodeRuntimeView* sibling = parent->right;
        if (sibling == head) {
          node = parent;
          parent = node->parent;
          continue;
        }
        if (sibling->color == 0u) {
          sibling->color = 1u;
          parent->color = 0u;
          WeakSetRotateLeft(set, parent);
          sibling = parent->right;
        }

        const bool leftBlack = sibling->left == nullptr || sibling->left->isNil != 0u || sibling->left->color == 1u;
        const bool rightBlack = sibling->right == nullptr || sibling->right->isNil != 0u || sibling->right->color == 1u;
        if (leftBlack && rightBlack) {
          sibling->color = 0u;
          node = parent;
          parent = node->parent;
          continue;
        }

        if (sibling->right == nullptr || sibling->right->isNil != 0u || sibling->right->color == 1u) {
          if (sibling->left != nullptr && sibling->left->isNil == 0u) {
            sibling->left->color = 1u;
          }
          sibling->color = 0u;
          WeakSetRotateRight(set, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = 1u;
        if (sibling->right != nullptr && sibling->right->isNil == 0u) {
          sibling->right->color = 1u;
        }
        WeakSetRotateLeft(set, parent);
        node = head->parent;
        break;
      }

      UserEntityWeakSetNodeRuntimeView* sibling = parent->left;
      if (sibling == head) {
        node = parent;
        parent = node->parent;
        continue;
      }
      if (sibling->color == 0u) {
        sibling->color = 1u;
        parent->color = 0u;
        WeakSetRotateRight(set, parent);
        sibling = parent->left;
      }

      const bool rightBlack = sibling->right == nullptr || sibling->right->isNil != 0u || sibling->right->color == 1u;
      const bool leftBlack = sibling->left == nullptr || sibling->left->isNil != 0u || sibling->left->color == 1u;
      if (rightBlack && leftBlack) {
        sibling->color = 0u;
        node = parent;
        parent = node->parent;
        continue;
      }

      if (sibling->left == nullptr || sibling->left->isNil != 0u || sibling->left->color == 1u) {
        if (sibling->right != nullptr && sibling->right->isNil == 0u) {
          sibling->right->color = 1u;
        }
        sibling->color = 0u;
        WeakSetRotateLeft(set, sibling);
        sibling = parent->left;
      }

      sibling->color = parent->color;
      parent->color = 1u;
      if (sibling->left != nullptr && sibling->left->isNil == 0u) {
        sibling->left->color = 1u;
      }
      WeakSetRotateRight(set, parent);
      node = head->parent;
      break;
    }

    if (node != nullptr && node->isNil == 0u) {
      node->color = 1u;
    }
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetEraseNodeAndAdvance(
    UserEntityWeakSetRuntimeView& set,
    UserEntityWeakSetNodeRuntimeView* const node
  )
  {
    if (set.head == nullptr || node == nullptr || node->isNil != 0u) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    UserEntityWeakSetNodeRuntimeView* const head = set.head;
    UserEntityWeakSetNodeRuntimeView* const next = WeakSetNextNode(node, head);

    UserEntityWeakSetNodeRuntimeView* removed = node;
    UserEntityWeakSetNodeRuntimeView* spliceTarget = node;
    std::uint8_t removedColor = spliceTarget->color;
    UserEntityWeakSetNodeRuntimeView* fixNode = head;
    UserEntityWeakSetNodeRuntimeView* fixParent = head;

    if (node->left == nullptr || node->left->isNil != 0u) {
      fixNode = node->right;
      fixParent = node->parent;
      WeakSetReplaceSubtree(set, node, node->right);
    } else if (node->right == nullptr || node->right->isNil != 0u) {
      fixNode = node->left;
      fixParent = node->parent;
      WeakSetReplaceSubtree(set, node, node->left);
    } else {
      spliceTarget = WeakSetMinNode(node->right, head);
      removedColor = spliceTarget->color;
      fixNode = spliceTarget->right;
      if (spliceTarget->parent == node) {
        fixParent = spliceTarget;
        if (fixNode != nullptr && fixNode->isNil == 0u) {
          fixNode->parent = spliceTarget;
        }
      } else {
        fixParent = spliceTarget->parent;
        WeakSetReplaceSubtree(set, spliceTarget, spliceTarget->right);
        spliceTarget->right = node->right;
        spliceTarget->right->parent = spliceTarget;
      }

      WeakSetReplaceSubtree(set, node, spliceTarget);
      spliceTarget->left = node->left;
      spliceTarget->left->parent = spliceTarget;
      spliceTarget->color = node->color;
    }

    WeakSetUnlinkOwnerRef(removed->weakEntityLink);
    ::operator delete(removed);

    if (set.size > 0u) {
      --set.size;
    }
    if (removedColor == 1u) {
      WeakSetFixupAfterErase(set, fixNode, fixParent);
    }

    WeakSetRecomputeExtrema(set);
    return next;
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetPruneTombstonesAndFindLive(
    UserEntityWeakSetRuntimeView& set,
    UserEntityWeakSetNodeRuntimeView* const start
  );

  void WeakSetDestroySubtree(UserEntityWeakSetNodeRuntimeView* const node)
  {
    UserEntityWeakSetNodeRuntimeView* cursor = node;
    while (cursor != nullptr && cursor->isNil == 0u) {
      WeakSetDestroySubtree(cursor->right);

      UserEntityWeakSetNodeRuntimeView* const left = cursor->left;
      WeakSetUnlinkOwnerRef(cursor->weakEntityLink);
      ::operator delete(cursor);
      cursor = left;
    }
  }

  /**
   * Address: 0x007B33B0 (FUN_007B33B0, std::map_uint_WeakPtr_UserEntity::erase)
   *
   * What it does:
   * Erases one half-open weak-set node range and preserves the binary iterator
   * contract by returning the first node that remains after the range.
   */
  [[nodiscard]] UserEntityWeakSetNodeRuntimeView** EraseUserEntityWeakSetRange(
    UserEntityWeakSetRuntimeView* const set,
    UserEntityWeakSetNodeRuntimeView** const outNode,
    UserEntityWeakSetNodeRuntimeView* const first,
    UserEntityWeakSetNodeRuntimeView* const last
  )
  {
    if (set == nullptr || set->head == nullptr) {
      *outNode = nullptr;
      return outNode;
    }

    UserEntityWeakSetNodeRuntimeView* node = first;
    UserEntityWeakSetNodeRuntimeView* const head = set->head;
    if (first == head->left && last == head) {
      WeakSetDestroySubtree(head->parent);
      head->parent = head;
      set->size = 0u;
      head->left = head;
      head->right = head;
      *outNode = head->left;
      return outNode;
    }

    while (node != last && node != nullptr && node != head) {
      node = WeakSetEraseNodeAndAdvance(*set, node);
    }

    *outNode = node;
    return outNode;
  }

  /**
   * Address: 0x007B2530 (FUN_007B2530, std::map_uint_WeakPtr_UserEntity::~map)
   *
   * What it does:
   * Releases one weak-set tree object, clears its head slot, and zeroes the
   * live element count after full-range teardown.
   */
  [[nodiscard]] std::int32_t ReleaseUserEntityWeakSetStorage(UserEntityWeakSetRuntimeView* const set)
  {
    if (set == nullptr) {
      return 0;
    }

    UserEntityWeakSetNodeRuntimeView* cursor = nullptr;
    (void)EraseUserEntityWeakSetRange(set, &cursor, set->head != nullptr ? set->head->left : nullptr, set->head);
    if (set->head != nullptr) {
      ::operator delete(set->head);
      set->head = nullptr;
    }
    set->size = 0u;
    return 0;
  }

  /**
   * Address: 0x007B2650 (FUN_007B2650, sub_7B2650)
   *
   * What it does:
   * Releases one weak-set map storage lane by erasing all nodes, deleting the
   * head sentinel, and zeroing `{head,size}`.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t ReleaseUserEntityWeakSetStorageCompat(UserEntityWeakSetRuntimeView* const set)
  {
    return ReleaseUserEntityWeakSetStorage(set);
  }

  /**
   * Address: 0x00838AE0 (FUN_00838AE0, sub_838AE0)
   *
   * What it does:
   * Counts live weak-set entries, pruning tombstone nodes along the way so the
   * iterator walk matches the binary's pruning-and-count loop.
   */
  [[nodiscard]] std::int32_t CountLiveUserEntityWeakSetEntriesAndPrune(UserEntityWeakSetRuntimeView* const set)
  {
    if (set == nullptr || set->head == nullptr) {
      return 0;
    }

    UserEntityWeakSetNodeRuntimeView* node = WeakSetPruneTombstonesAndFindLive(*set, set->head->left);
    if (node == nullptr || node == set->head) {
      return 0;
    }

    std::int32_t count = 0;
    do {
      ++count;
      node = WeakSetNextNode(node, set->head);
      if (node != set->head) {
        node = WeakSetPruneTombstonesAndFindLive(*set, node);
      }
    } while (node != nullptr && node != set->head);

    return count;
  }

  [[nodiscard]] UserEntityWeakSetNodeRuntimeView* WeakSetPruneTombstonesAndFindLive(
    UserEntityWeakSetRuntimeView& set,
    UserEntityWeakSetNodeRuntimeView* const start
  )
  {
    UserEntityWeakSetNodeRuntimeView* node = start;
    if (set.head == nullptr) {
      return nullptr;
    }

    while (node != set.head) {
      if (WeakSetNodeHasLiveOwner(node)) {
        break;
      }

      node = WeakSetEraseNodeAndAdvance(set, node);
    }

    return node;
  }

  void AppendEntityUnitLuaObject(
    LuaPlus::LuaObject& resultTable,
    std::int32_t& luaIndex,
    UserEntity* const entity
  )
  {
    if (entity == nullptr) {
      return;
    }

    UserUnit* const userUnit = entity->IsUserUnit();
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (iunitBridge == nullptr) {
      return;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(luaIndex, unitObject);
    ++luaIndex;
  }

  [[nodiscard]] UserEntityWeakSetRuntimeView* ResolveIdleUnitSetView(
    UserArmy* const army,
    const bool useFactorySet
  ) noexcept
  {
    if (army == nullptr) {
      return nullptr;
    }

    auto* const runtimeView = reinterpret_cast<UserArmyIdleSetsRuntimeView*>(army);
    return useFactorySet ? &runtimeView->idleFactoryUnits : &runtimeView->idleEngineerUnits;
  }

  [[nodiscard]] const UserArmyAvatarVectorRuntimeView& ResolveArmyAvatarVectorView(const UserArmy* const army) noexcept
  {
    return reinterpret_cast<const UserArmyAvatarRuntimeView*>(army)->avatarWeakRefs;
  }

  struct UserUnitAssistTargetRuntimeView
  {
    std::uint8_t pad_0000_03C0[0x3C0];
    UserEntityWeakRefRuntimeView assistTargetLink; // +0x3C0
  };
  static_assert(
    offsetof(UserUnitAssistTargetRuntimeView, assistTargetLink) == 0x3C0,
    "UserUnitAssistTargetRuntimeView::assistTargetLink offset must be 0x3C0"
  );

  [[nodiscard]] UserUnit* ResolveAssistTargetUnit(const UserUnit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    const auto* const runtime = reinterpret_cast<const UserUnitAssistTargetRuntimeView*>(unit);
    UserEntity* const assistEntity = DecodeLinkedUserEntity(runtime->assistTargetLink);
    return assistEntity ? assistEntity->IsUserUnit() : nullptr;
  }

  struct UserUnitScriptBitRuntimeView
  {
    std::uint8_t pad_0000_03A8[0x3A8];
    std::int32_t scriptBitMask; // +0x3A8
  };
  static_assert(
    offsetof(UserUnitScriptBitRuntimeView, scriptBitMask) == 0x3A8,
    "UserUnitScriptBitRuntimeView::scriptBitMask offset must be 0x3A8"
  );

  [[nodiscard]] std::int64_t BuildScriptBitMask(const int bitIndex) noexcept
  {
    const std::uint32_t bitShift = static_cast<std::uint32_t>(bitIndex);
    return bitShift < 64u ? static_cast<std::int64_t>(1ull << bitShift) : 0;
  }

  [[nodiscard]] std::int64_t GetUserUnitScriptBitMask(const UserUnit* const userUnit) noexcept
  {
    if (userUnit == nullptr) {
      return 0;
    }

    const auto* const view = reinterpret_cast<const UserUnitScriptBitRuntimeView*>(userUnit);
    return static_cast<std::int64_t>(view->scriptBitMask);
  }

  struct UserSessionEntityMapNodeView
  {
    UserSessionEntityMapNodeView* left;   // +0x00
    UserSessionEntityMapNodeView* parent; // +0x04
    UserSessionEntityMapNodeView* right;  // +0x08
    std::int32_t key;                     // +0x0C
    UserEntity* value;                    // +0x10
    std::uint8_t color;                   // +0x14
    std::uint8_t isNil;                   // +0x15
    std::uint8_t pad_0016_0017[0x02];
  };
  static_assert(
    offsetof(UserSessionEntityMapNodeView, key) == 0x0C, "UserSessionEntityMapNodeView::key offset must be 0x0C"
  );
  static_assert(
    offsetof(UserSessionEntityMapNodeView, value) == 0x10,
    "UserSessionEntityMapNodeView::value offset must be 0x10"
  );
  static_assert(
    offsetof(UserSessionEntityMapNodeView, isNil) == 0x15,
    "UserSessionEntityMapNodeView::isNil offset must be 0x15"
  );
  static_assert(sizeof(UserSessionEntityMapNodeView) == 0x18, "UserSessionEntityMapNodeView size must be 0x18");

  struct UserSessionEntityMapView
  {
    void* allocatorProxy;                // +0x00
    UserSessionEntityMapNodeView* head;  // +0x04
    std::uint32_t size;                  // +0x08
  };
  static_assert(
    offsetof(UserSessionEntityMapView, head) == 0x04, "UserSessionEntityMapView::head offset must be 0x04"
  );
  static_assert(
    offsetof(UserSessionEntityMapView, size) == 0x08, "UserSessionEntityMapView::size offset must be 0x08"
  );
  static_assert(sizeof(UserSessionEntityMapView) == 0x0C, "UserSessionEntityMapView size must be 0x0C");
  static_assert(offsetof(CWldSession, mUnknownOwner44) == 0x44, "CWldSession::mUnknownOwner44 offset must be 0x44");

  struct UserUnitLuaObjectRuntimeView
  {
    std::uint8_t pad_0000_0170[0x170];
    LuaPlus::LuaObject luaObject; // +0x170
  };
  static_assert(
    offsetof(UserUnitLuaObjectRuntimeView, luaObject) == 0x170,
    "UserUnitLuaObjectRuntimeView::luaObject offset must be 0x170"
  );

  [[nodiscard]] const UserSessionEntityMapView& GetUserSessionEntityMapView(const CWldSession* const session) noexcept
  {
    return *reinterpret_cast<const UserSessionEntityMapView*>(
      reinterpret_cast<const std::uint8_t*>(session) + offsetof(CWldSession, mUnknownOwner44)
    );
  }

  [[nodiscard]] const UserSessionEntityMapNodeView*
  FindUserSessionEntityNode(const UserSessionEntityMapView& map, const std::int32_t entityId) noexcept
  {
    const UserSessionEntityMapNodeView* const head = map.head;
    if (head == nullptr) {
      return nullptr;
    }

    const UserSessionEntityMapNodeView* result = head;
    const UserSessionEntityMapNodeView* node = head->parent;
    while (node != nullptr && node != head && node->isNil == 0u) {
      if (node->key >= entityId) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    if (result == head || entityId < result->key) {
      return head;
    }

    return result;
  }

  [[nodiscard]] UserEntity*
  FindUserSessionEntityById(CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    const UserSessionEntityMapView& entityMap = GetUserSessionEntityMapView(session);
    const UserSessionEntityMapNodeView* const node = FindUserSessionEntityNode(entityMap, entityId);
    if (node == nullptr || node == entityMap.head) {
      return nullptr;
    }
    return node->value;
  }

  [[nodiscard]] UserUnit* ResolveSelectableTransportAttachmentParent(UserUnit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    auto* const entity = reinterpret_cast<UserEntity*>(unit);
    const std::uint32_t attachmentParentRef = entity->mVariableData.mAttachmentParentRef;
    if (attachmentParentRef == 0u || attachmentParentRef == ToRaw(EEntityIdSentinel::Invalid)) {
      return nullptr;
    }

    UserEntity* const attachmentParentEntity = FindUserSessionEntityById(
      entity->mSession,
      static_cast<std::int32_t>(attachmentParentRef)
    );
    if (attachmentParentEntity == nullptr || !attachmentParentEntity->IsSelectable()) {
      return nullptr;
    }

    UserUnit* const attachmentParentUnit = attachmentParentEntity->IsUserUnit();
    if (attachmentParentUnit == nullptr) {
      return nullptr;
    }

    static const msvc8::string kTransportationCategory("TRANSPORTATION");
    return attachmentParentEntity->IsInCategory(kTransportationCategory) ? attachmentParentUnit : nullptr;
  }

  void AppendSelectionUnitUnique(msvc8::vector<UserUnit*>& selectionUnits, UserUnit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    if (std::find(selectionUnits.begin(), selectionUnits.end(), unit) == selectionUnits.end()) {
      selectionUnits.push_back(unit);
    }
  }

  [[nodiscard]] UserSessionEntityMapNodeView* UserSessionEntityMapMinNode(
    UserSessionEntityMapNodeView* node,
    UserSessionEntityMapNodeView* const head
  ) noexcept
  {
    while (node != nullptr && node != head && node->left != head) {
      node = node->left;
    }
    return node != nullptr ? node : head;
  }

  [[nodiscard]] UserSessionEntityMapNodeView* UserSessionEntityMapFirstNode(const UserSessionEntityMapView& map) noexcept
  {
    UserSessionEntityMapNodeView* const head = map.head;
    if (head == nullptr || head->isNil == 0u) {
      return nullptr;
    }

    UserSessionEntityMapNodeView* const root = head->parent;
    if (root == nullptr || root == head || root->isNil != 0u) {
      return head;
    }

    return UserSessionEntityMapMinNode(root, head);
  }

  [[nodiscard]] UserSessionEntityMapNodeView* UserSessionEntityMapNextNode(
    UserSessionEntityMapNodeView* node,
    UserSessionEntityMapNodeView* const head
  ) noexcept
  {
    if (node == nullptr || head == nullptr || node == head) {
      return head;
    }

    if (node->right != head) {
      return UserSessionEntityMapMinNode(node->right, head);
    }

    UserSessionEntityMapNodeView* parent = node->parent;
    while (parent != nullptr && parent != head && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }

    return parent != nullptr ? parent : head;
  }

  [[nodiscard]] const UserUnitLuaObjectRuntimeView& GetUserUnitLuaObjectView(const UserUnit* const userUnit) noexcept
  {
    return *reinterpret_cast<const UserUnitLuaObjectRuntimeView*>(userUnit);
  }

  /**
   * The reflected reference is assembled from the userdata HEADER, not read out
   * of its payload. This fork carries the `gpg::RType*` in `Udata::len`, and the
   * value itself starts one header past the allocation, which is exactly what
   * `LuaPlus::LuaObject::GetUserData` (0x00907540) does:
   *
   *     lea edx, [ecx+10h]   ; mObj  = payload, laid out after the header
   *     mov ecx, [ecx+0Ch]   ; mType = Udata::len reinterpreted as RType*
   *
   * Reading `*(gpg::RRef*)lua_touserdata(...)` instead - as this helper used to -
   * takes the first eight payload bytes as if they were a reference. For a
   * `_c_object` slot those bytes are the `CScriptObject*` value followed by
   * whatever the allocator left, so every upcast failed and each caller reported
   * "Expected a game object" for a perfectly good object.
   */
  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = CScriptObject::GetPointerType();
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedUserUnitType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(UserUnit));
    }
    return sType;
  }

  [[nodiscard]] CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
    return static_cast<CScriptObject**>(upcast.mObj);
  }

  [[nodiscard]] UserUnit* ResolveUserUnitOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserUnitType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<UserUnit*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(EntityCategorySet));
    }
    return sType;
  }

  [[nodiscard]] EntityCategorySet* ResolveEntityCategorySetFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    if (gpg::RType* const expectedType = CachedEntityCategorySetType(); expectedType != nullptr) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, expectedType);
      if (upcast.mObj != nullptr) {
        return static_cast<EntityCategorySet*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr
        && (std::strstr(typeName, "EntityCategory") != nullptr || std::strstr(typeName, "BVSet") != nullptr)) {
      return static_cast<EntityCategorySet*>(userDataRef.mObj);
    }

    return nullptr;
  }

  [[nodiscard]] const RUnitBlueprint* ResolveEntityCategoryFilterBlueprint(
    const LuaPlus::LuaObject& valueObject,
    CWldSession* const session,
    LuaPlus::LuaState* const state
  )
  {
    if (valueObject.IsString()) {
      const char* const blueprintText = valueObject.GetString();
      if (!blueprintText || !session || !session->mRules) {
        return nullptr;
      }

      RResId blueprintId{};
      gpg::STR_SetFilename(&blueprintId.name, blueprintText);
      return session->mRules->GetUnitBlueprint(blueprintId);
    }

    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    if (!userUnit) {
      return nullptr;
    }

    const IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    return iunitBridge ? iunitBridge->GetBlueprint() : nullptr;
  }

  [[nodiscard]] const REntityBlueprint* ResolveEntityCategoryCountBlueprint(
    const LuaPlus::LuaObject& valueObject,
    RRuleGameRulesImpl* const rules
  )
  {
    if (valueObject.IsString()) {
      const char* const blueprintText = valueObject.GetString();
      if (!blueprintText || !rules) {
        return nullptr;
      }

      RResId blueprintId{};
      gpg::STR_SetFilename(&blueprintId.name, blueprintText);
      return rules->GetEntityBlueprint(blueprintId);
    }

    Entity* const entity = SCR_FromLuaNoError_Entity(valueObject);
    return entity ? entity->BluePrint : nullptr;
  }

  [[nodiscard]] const BVIntSet& CategoryWordRangeAsBVIntSet(const CategoryWordRangeView& range) noexcept
  {
    return range.mBits;
  }

  /**
   * Address: 0x00758DB0 (FUN_00758DB0, sub_758DB0)
   *
   * What it does:
   * Copies the active sync-filter `maskB` bitset payload into one temporary
   * `BVIntSet` used by `cfunc_DebugGetSelectionL`.
   */
  void CopyDebugSelectionMaskB(const Sim& sim, BVIntSet& outSelectionIds)
  {
    outSelectionIds.mReservedMetaWord = 0u;
    outSelectionIds.mFirstWordIndex = sim.mSyncFilter.maskB.mFirstWordIndex;
    outSelectionIds.mWords.ResetFrom(sim.mSyncFilter.maskB.mWords);
  }

  [[nodiscard]] Entity* ResolveRequiredEntityLuaArg(
    LuaPlus::LuaState* const state,
    const char* const helpText
  )
  {
    if (!state || !state->m_state) {
      return nullptr;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    return SCR_FromLua_Entity(entityObject, state);
  }

  template <typename TEntityLike>
  int PushEntityScriptObjectOrNil(LuaPlus::LuaState* const state, TEntityLike* const object)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    if (object == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    object->mLuaObj.PushStack(state);
    return 1;
  }

  template <class THandler>
  void ForEachSelectedUnit(SEntitySetTemplateUnit* const selectedUnits, THandler&& handler)
  {
    if (selectedUnits == nullptr) {
      return;
    }

    for (Entity* const* it = selectedUnits->mVec.begin(); it != selectedUnits->mVec.end(); ++it) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (unit != nullptr) {
        handler(*unit);
      }
    }
  }

  template <typename TValue>
  void LuaPushNumberField(lua_State* const state, const char* const key, const TValue value)
  {
    lua_pushstring(state, key);
    lua_pushnumber(state, static_cast<lua_Number>(value));
    lua_rawset(state, -3);
  }

  void SetArmyValidCommandSourceBit(
    CArmyImpl& army,
    const std::int32_t sourceIndex,
    const bool enabled
  ) noexcept
  {
    Set& validSources = army.MohoSetValidCommandSources;

    const std::uint32_t source = static_cast<std::uint32_t>(sourceIndex);
    const std::uint32_t wordOffset = source >> (5u - static_cast<std::uint32_t>(validSources.baseWordIndex));
    std::uint32_t* const word = validSources.items_begin + wordOffset;
    if (word >= validSources.items_end) {
      validSources.items_end = word + 1;
    }

    const std::uint32_t bitMask = 1u << (source & 31u);
    if (enabled) {
      *word |= bitMask;
    } else {
      *word &= ~bitMask;
    }
  }

  struct PropCreateTransformWords
  {
    float orientX;
    float orientY;
    float orientZ;
    float orientW;
    float posX;
    float posY;
    float posZ;
  };

  static_assert(sizeof(PropCreateTransformWords) == 0x1C, "PropCreateTransformWords size must be 0x1C");

  struct UnitTrackStatsRuntimeView
  {
    std::uint8_t pad_0000[0x200];
    bool trackingEnabled;
  };
  static_assert(
    offsetof(UnitTrackStatsRuntimeView, trackingEnabled) == 0x200,
    "UnitTrackStatsRuntimeView::trackingEnabled offset must be 0x200"
  );

  bool ParseBoolLiteral(const char* text, bool& outValue)
  {
    if (gpg::STR_EqualsNoCase(text, "true")) {
      outValue = true;
      return true;
    }

    if (gpg::STR_EqualsNoCase(text, "false")) {
      outValue = false;
      return true;
    }

    return false;
  }

  struct CEconStorageRuntimeView
  {
    std::uint8_t* economyRuntime; // +0x00
    float amounts[4];             // +0x04
  };
  static_assert(
    offsetof(CEconStorageRuntimeView, economyRuntime) == 0x00,
    "CEconStorageRuntimeView::economyRuntime offset must be 0x00"
  );
  static_assert(
    offsetof(CEconStorageRuntimeView, amounts) == 0x04,
    "CEconStorageRuntimeView::amounts offset must be 0x04"
  );

  void ApplyEconStorageDelta(CEconStorageRuntimeView& storage, const std::int32_t direction)
  {
    if (storage.economyRuntime == nullptr) {
      return;
    }

    const std::int64_t signedDirection = static_cast<std::int64_t>(direction);
    constexpr std::size_t kAccumOffset = 0x40;
    constexpr std::size_t kAccumCount = 4;
    for (std::size_t i = 0; i < kAccumCount; ++i) {
      auto* const accumulator =
        reinterpret_cast<std::int64_t*>(storage.economyRuntime + kAccumOffset + (i * sizeof(std::int64_t)));
      const std::int64_t delta = static_cast<std::int64_t>(storage.amounts[i]) * signedDirection;
      *accumulator += delta;
    }
  }

  [[nodiscard]]
  CEconStorageRuntimeView* GetArmyEconStorage(CArmyImpl& army) noexcept
  {
    CSimArmyEconomyInfo* const economyInfo = army.GetEconomy();
    return economyInfo != nullptr ? reinterpret_cast<CEconStorageRuntimeView*>(economyInfo->storageDelta) : nullptr;
  }

  template <typename TInt>
  [[nodiscard]] std::uint32_t PackOpaqueArmyColor(const TInt red, const TInt green, const TInt blue) noexcept
  {
    const std::int32_t redLane = (static_cast<std::int32_t>(red) | 0xFFFFFF00) << 16;
    const std::int32_t greenLane = (static_cast<std::int32_t>(green) & 0xFF) << 8;
    const std::int32_t blueLane = static_cast<std::int32_t>(blue) & 0xFF;
    return static_cast<std::uint32_t>(redLane | greenLane | blueLane);
  }

  using ArmyListCursor = CArmyImpl* const*;

  template <typename TIterator>
  [[nodiscard]] TIterator FindArmyByNameCursor(TIterator begin, const TIterator end, const std::string_view armyName)
  {
    return std::find_if(begin, end, [armyName](const CArmyImpl* const army) -> bool {
      return army != nullptr && army->ArmyName.view() == armyName;
    });
  }

  /**
   * Address: 0x0070AD00 (FUN_0070AD00, func_FindArmyWithName)
   *
   * What it does:
   * Scans the army pointer range and returns the first entry whose `ArmyName`
   * matches `armyName` exactly, or `end` when no match exists.
   */
  [[nodiscard]] ArmyListCursor
  func_FindArmyWithName(ArmyListCursor begin, const ArmyListCursor end, const std::string_view armyName)
  {
    return FindArmyByNameCursor(begin, end, armyName);
  }

  /**
   * Address: 0x0070AC50 (FUN_0070AC50, func_GetArmyWithName)
   *
   * What it does:
   * Thin wrapper around `func_FindArmyWithName` used by army-Lua argument
   * decoding helpers.
   */
  [[nodiscard]] ArmyListCursor
  func_GetArmyWithName(ArmyListCursor begin, const ArmyListCursor end, const std::string_view armyName)
  {
    return func_FindArmyWithName(begin, end, armyName);
  }

  template <int StackIndex>
  [[nodiscard]] std::uint8_t ReadLuaColorByteArg(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaStackObject arg(state, StackIndex);
    if (lua_type(state->m_state, StackIndex) != LUA_TNUMBER) {
      arg.TypeError("integer");
    }

    const auto value = static_cast<std::int32_t>(lua_tonumber(state->m_state, StackIndex));
    return static_cast<std::uint8_t>(value & 0xFF);
  }

  [[nodiscard]] CmdId ReadLuaCommandIdArg(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject arg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&arg, "integer");
    }

    // Binary lane uses an x87 integer-store conversion and consumes the low dword.
    const std::int64_t truncated = static_cast<std::int64_t>(lua_tonumber(state->m_state, stackIndex));
    return static_cast<CmdId>(static_cast<std::uint32_t>(truncated));
  }

  /**
   * Address: 0x006E0850 (FUN_006E0850)
   *
   * What it does:
   * Extracts the low 24-bit command-id/index payload lane from packed command
   * id storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ExtractPackedCommandIdLow24Bits(const std::uint32_t* const packedValue)
    noexcept
  {
    return packedValue != nullptr ? (*packedValue & 0x00FFFFFFu) : 0u;
  }

  using SpecialFileTypeRuntime = moho::ESpecialFileType;

  [[noreturn]] void ThrowInvalidSpecialFileType(const char* const lexical)
  {
    throw std::runtime_error(gpg::STR_Printf("Invalid special file type %s", lexical != nullptr ? lexical : "").to_std());
  }

  [[nodiscard]] bool TryParseSpecialFileType(
    const char* const lexical,
    SpecialFileTypeRuntime& outType
  ) noexcept
  {
    if (lexical == nullptr) {
      return false;
    }

    const std::string_view text(lexical);
    if (text == "SaveGame" || text == "SFT_SaveGame") {
      outType = SpecialFileTypeRuntime::SaveGame;
      return true;
    }
    if (text == "Replay" || text == "SFT_Replay") {
      outType = SpecialFileTypeRuntime::Replay;
      return true;
    }
    if (text == "Screenshot" || text == "SFT_Screenshot") {
      outType = SpecialFileTypeRuntime::Screenshot;
      return true;
    }
    if (text == "CampaignSave" || text == "SFT_CampaignSave") {
      outType = SpecialFileTypeRuntime::CampaignSave;
      return true;
    }

    char* end = nullptr;
    const long numericValue = std::strtol(lexical, &end, 10);
    if (end != lexical && end != nullptr && *end == '\0' && numericValue >= 0 && numericValue <= 3) {
      outType = static_cast<SpecialFileTypeRuntime>(numericValue);
      return true;
    }

    return false;
  }

  [[nodiscard]] msvc8::string BuildSpecialFilePathDirectory(const SpecialFileTypeRuntime type)
  {
    switch (type) {
      case SpecialFileTypeRuntime::SaveGame:
      case SpecialFileTypeRuntime::CampaignSave:
        return USER_GetSaveGameDir();
      case SpecialFileTypeRuntime::Replay:
        return USER_GetReplayDir();
      case SpecialFileTypeRuntime::Screenshot:
        return USER_GetScreenshotDir();
    }
    return msvc8::string{};
  }

  [[nodiscard]] msvc8::string BuildSpecialFilePathExtension(const SpecialFileTypeRuntime type)
  {
    switch (type) {
      case SpecialFileTypeRuntime::SaveGame:
        return USER_GetSaveGameExt();
      case SpecialFileTypeRuntime::Replay:
        return USER_GetReplayExt();
      case SpecialFileTypeRuntime::Screenshot:
        return msvc8::string("bmp");
      case SpecialFileTypeRuntime::CampaignSave:
        return USER_GetCampaignSaveExt();
    }
    return msvc8::string{};
  }

  struct SpecialFilesLegacyStringRuntimeView
  {
    union
    {
      char inlineStorage[16];
      char* heapStorage;
    };
    std::uint32_t size;      // +0x10
    std::uint32_t capacity;  // +0x14
  };
  static_assert(sizeof(SpecialFilesLegacyStringRuntimeView) == 0x18, "SpecialFilesLegacyStringRuntimeView size must be 0x18");
  static_assert(
    offsetof(SpecialFilesLegacyStringRuntimeView, size) == 0x10,
    "SpecialFilesLegacyStringRuntimeView::size offset must be 0x10"
  );
  static_assert(
    offsetof(SpecialFilesLegacyStringRuntimeView, capacity) == 0x14,
    "SpecialFilesLegacyStringRuntimeView::capacity offset must be 0x14"
  );

  struct SpecialFilesMapNodeRuntimeView
  {
    SpecialFilesMapNodeRuntimeView* left;    // +0x00
    SpecialFilesMapNodeRuntimeView* parent;  // +0x04
    SpecialFilesMapNodeRuntimeView* right;   // +0x08
    std::uint32_t lane0C;                    // +0x0C
    SpecialFilesLegacyStringRuntimeView key; // +0x10
    std::string* filesBegin;                 // +0x28
    std::string* filesEnd;                   // +0x2C
    std::string* filesCapacityEnd;           // +0x30
    std::uint32_t lane34;                    // +0x34
    std::uint8_t color;                      // +0x38
    std::uint8_t isNil;                      // +0x39
    std::uint8_t pad3A[2];                   // +0x3A
  };
  static_assert(sizeof(SpecialFilesMapNodeRuntimeView) == 0x3C, "SpecialFilesMapNodeRuntimeView size must be 0x3C");
  static_assert(offsetof(SpecialFilesMapNodeRuntimeView, key) == 0x10, "SpecialFilesMapNodeRuntimeView::key offset must be 0x10");
  static_assert(
    offsetof(SpecialFilesMapNodeRuntimeView, filesBegin) == 0x28,
    "SpecialFilesMapNodeRuntimeView::filesBegin offset must be 0x28"
  );
  static_assert(
    offsetof(SpecialFilesMapNodeRuntimeView, isNil) == 0x39,
    "SpecialFilesMapNodeRuntimeView::isNil offset must be 0x39"
  );

  struct SpecialFilesMapStorageRuntimeView
  {
    void* proxy;                            // +0x00
    SpecialFilesMapNodeRuntimeView* head;  // +0x04
    std::uint32_t size;                    // +0x08
  };
  static_assert(sizeof(SpecialFilesMapStorageRuntimeView) == 0x0C, "SpecialFilesMapStorageRuntimeView size must be 0x0C");
  static_assert(
    offsetof(SpecialFilesMapStorageRuntimeView, head) == 0x04,
    "SpecialFilesMapStorageRuntimeView::head offset must be 0x04"
  );
  static_assert(
    offsetof(SpecialFilesMapStorageRuntimeView, size) == 0x08,
    "SpecialFilesMapStorageRuntimeView::size offset must be 0x08"
  );

  constexpr std::uint8_t kSpecialFilesMapRed = 0u;
  constexpr std::uint8_t kSpecialFilesMapBlack = 1u;

  void DestroySpecialFilesStringRange(std::string* begin, std::string* const end) noexcept
  {
    while (begin != end) {
      begin->~basic_string<char>();
      ++begin;
    }
  }

  void ResetSpecialFilesLegacyStringStorage(SpecialFilesLegacyStringRuntimeView& storage) noexcept
  {
    if (storage.capacity >= 0x10u) {
      ::operator delete(static_cast<void*>(storage.heapStorage));
    }

    storage.size = 0u;
    storage.capacity = 0x0Fu;
    storage.inlineStorage[0] = '\0';
  }

  [[nodiscard]] SpecialFilesMapNodeRuntimeView* SpecialFilesMapTreeMin(
    SpecialFilesMapNodeRuntimeView* node,
    SpecialFilesMapNodeRuntimeView* const head
  ) noexcept
  {
    while (node->left != head) {
      node = node->left;
    }
    return node;
  }

  [[nodiscard]] SpecialFilesMapNodeRuntimeView* SpecialFilesMapTreeMax(
    SpecialFilesMapNodeRuntimeView* node,
    SpecialFilesMapNodeRuntimeView* const head
  ) noexcept
  {
    while (node->right != head) {
      node = node->right;
    }
    return node;
  }

  [[nodiscard]] std::uint8_t SpecialFilesMapNodeColor(
    const SpecialFilesMapNodeRuntimeView* const node,
    const SpecialFilesMapNodeRuntimeView* const head
  ) noexcept
  {
    if (node == nullptr || node == head) {
      return kSpecialFilesMapBlack;
    }
    return node->color;
  }

  /**
   * Address: 0x00849D40 (FUN_00849D40)
   *
   * What it does:
   * Left-rotates one node of the special-files map, relinking the pivot's
   * left subtree, parent pointer, and the parent's child slot.
   */

  void RotateSpecialFilesMapLeft(
    SpecialFilesMapStorageRuntimeView& map,
    SpecialFilesMapNodeRuntimeView* const node
  ) noexcept
  {
    SpecialFilesMapNodeRuntimeView* const head = map.head;
    SpecialFilesMapNodeRuntimeView* const pivot = node->right;

    node->right = pivot->left;
    if (pivot->left != head) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  void RotateSpecialFilesMapRight(
    SpecialFilesMapStorageRuntimeView& map,
    SpecialFilesMapNodeRuntimeView* const node
  ) noexcept
  {
    // Address: 0x00849DB0 (FUN_00849DB0) -- right-rotates one node of the
    // special-files map, the mirror of RotateSpecialFilesMapLeft above.
    SpecialFilesMapNodeRuntimeView* const head = map.head;
    SpecialFilesMapNodeRuntimeView* const pivot = node->left;

    node->left = pivot->right;
    if (pivot->right != head) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node->parent == head) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void ReplaceSpecialFilesMapSubtree(
    SpecialFilesMapStorageRuntimeView& map,
    SpecialFilesMapNodeRuntimeView* const oldNode,
    SpecialFilesMapNodeRuntimeView* const newNode
  ) noexcept
  {
    SpecialFilesMapNodeRuntimeView* const head = map.head;
    if (oldNode->parent == head) {
      head->parent = newNode;
    } else if (oldNode == oldNode->parent->left) {
      oldNode->parent->left = newNode;
    } else {
      oldNode->parent->right = newNode;
    }

    if (newNode != head) {
      newNode->parent = oldNode->parent;
    }
  }

  /**
   * Address: 0x008497C0 (FUN_008497C0)
   *
   * What it does:
   * Advances one special-files map iterator node to its in-order successor
   * (leftmost of the right subtree, or the nearest ancestor this node is not
   * the right child of).
   */
  [[nodiscard]] SpecialFilesMapNodeRuntimeView* AdvanceSpecialFilesMapIteratorNode(
    SpecialFilesMapNodeRuntimeView* node,
    SpecialFilesMapNodeRuntimeView* const head
  ) noexcept
  {
    if (node->isNil != 0u) {
      return node;
    }

    if (node->right->isNil == 0u) {
      node = node->right;
      while (node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    SpecialFilesMapNodeRuntimeView* parent = node->parent;
    while (parent->isNil == 0u && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }
    return parent;
  }

  void FixupSpecialFilesMapErase(
    SpecialFilesMapStorageRuntimeView& map,
    SpecialFilesMapNodeRuntimeView* node,
    SpecialFilesMapNodeRuntimeView* nodeParent
  ) noexcept
  {
    SpecialFilesMapNodeRuntimeView* const head = map.head;

    while (node != head->parent && SpecialFilesMapNodeColor(node, head) == kSpecialFilesMapBlack) {
      if (node == nodeParent->left) {
        SpecialFilesMapNodeRuntimeView* sibling = nodeParent->right;
        if (SpecialFilesMapNodeColor(sibling, head) == kSpecialFilesMapRed) {
          sibling->color = kSpecialFilesMapBlack;
          nodeParent->color = kSpecialFilesMapRed;
          RotateSpecialFilesMapLeft(map, nodeParent);
          sibling = nodeParent->right;
        }

        if (sibling == head) {
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (
          SpecialFilesMapNodeColor(sibling->left, head) == kSpecialFilesMapBlack
          && SpecialFilesMapNodeColor(sibling->right, head) == kSpecialFilesMapBlack
        ) {
          sibling->color = kSpecialFilesMapRed;
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (SpecialFilesMapNodeColor(sibling->right, head) == kSpecialFilesMapBlack) {
          if (sibling->left != head) {
            sibling->left->color = kSpecialFilesMapBlack;
          }
          sibling->color = kSpecialFilesMapRed;
          RotateSpecialFilesMapRight(map, sibling);
          sibling = nodeParent->right;
        }

        sibling->color = nodeParent->color;
        nodeParent->color = kSpecialFilesMapBlack;
        if (sibling->right != head) {
          sibling->right->color = kSpecialFilesMapBlack;
        }
        RotateSpecialFilesMapLeft(map, nodeParent);
      } else {
        SpecialFilesMapNodeRuntimeView* sibling = nodeParent->left;
        if (SpecialFilesMapNodeColor(sibling, head) == kSpecialFilesMapRed) {
          sibling->color = kSpecialFilesMapBlack;
          nodeParent->color = kSpecialFilesMapRed;
          RotateSpecialFilesMapRight(map, nodeParent);
          sibling = nodeParent->left;
        }

        if (sibling == head) {
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (
          SpecialFilesMapNodeColor(sibling->right, head) == kSpecialFilesMapBlack
          && SpecialFilesMapNodeColor(sibling->left, head) == kSpecialFilesMapBlack
        ) {
          sibling->color = kSpecialFilesMapRed;
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (SpecialFilesMapNodeColor(sibling->left, head) == kSpecialFilesMapBlack) {
          if (sibling->right != head) {
            sibling->right->color = kSpecialFilesMapBlack;
          }
          sibling->color = kSpecialFilesMapRed;
          RotateSpecialFilesMapLeft(map, sibling);
          sibling = nodeParent->left;
        }

        sibling->color = nodeParent->color;
        nodeParent->color = kSpecialFilesMapBlack;
        if (sibling->left != head) {
          sibling->left->color = kSpecialFilesMapBlack;
        }
        RotateSpecialFilesMapRight(map, nodeParent);
      }

      node = head->parent;
      break;
    }

    if (node != head) {
      node->color = kSpecialFilesMapBlack;
    }
  }

  /**
   * Address: 0x0084A690 (FUN_0084A690)
   *
   * What it does:
   * Destroys one special-files map node payload (vector-of-strings + key
   * string storage) without freeing the node itself.
   */
  [[maybe_unused]] void DestroySpecialFilesMapNodePayload(SpecialFilesMapNodeRuntimeView* const node) noexcept
  {
    if (node->filesBegin != nullptr) {
      DestroySpecialFilesStringRange(node->filesBegin, node->filesEnd);
      ::operator delete(static_cast<void*>(node->filesBegin));
    }

    node->filesBegin = nullptr;
    node->filesEnd = nullptr;
    node->filesCapacityEnd = nullptr;
    ResetSpecialFilesLegacyStringStorage(node->key);
  }

  /**
   * Address: 0x00849CB0 (FUN_00849CB0)
   *
   * What it does:
   * Recursively destroys one subtree of special-files map nodes, including
   * string/vector payloads, then frees each node.
   */
  [[maybe_unused]] void DestroySpecialFilesMapSubtree(
    SpecialFilesMapStorageRuntimeView* const owner,
    SpecialFilesMapNodeRuntimeView* node
  ) noexcept
  {
    (void)owner;
    while (node != nullptr && node->isNil == 0u) {
      DestroySpecialFilesMapSubtree(owner, node->right);

      SpecialFilesMapNodeRuntimeView* const current = node;
      node = node->left;

      DestroySpecialFilesMapNodePayload(current);
      ::operator delete(static_cast<void*>(current));
    }
  }

  /**
   * Address: 0x00849900 (FUN_00849900)
   *
   * What it does:
   * Erases one special-files map node, restores RB-tree invariants, and writes
   * the next in-order iterator node into the output slot.
   */
  [[maybe_unused]] [[nodiscard]] SpecialFilesMapNodeRuntimeView** EraseSpecialFilesMapNodeAndAdvance(
    SpecialFilesMapStorageRuntimeView* const map,
    SpecialFilesMapNodeRuntimeView** const outNextNode,
    SpecialFilesMapNodeRuntimeView* const erasedNode
  )
  {
    SpecialFilesMapNodeRuntimeView* const head = map->head;
    if (erasedNode == nullptr || erasedNode->isNil != 0u) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    SpecialFilesMapNodeRuntimeView* const next = AdvanceSpecialFilesMapIteratorNode(erasedNode, head);

    SpecialFilesMapNodeRuntimeView* spliceNode = erasedNode;
    SpecialFilesMapNodeRuntimeView* fixNode = head;
    SpecialFilesMapNodeRuntimeView* fixParent = head;
    std::uint8_t removedColor = spliceNode->color;

    if (erasedNode->left == head) {
      fixNode = erasedNode->right;
      fixParent = erasedNode->parent;
      ReplaceSpecialFilesMapSubtree(*map, erasedNode, erasedNode->right);
    } else if (erasedNode->right == head) {
      fixNode = erasedNode->left;
      fixParent = erasedNode->parent;
      ReplaceSpecialFilesMapSubtree(*map, erasedNode, erasedNode->left);
    } else {
      spliceNode = SpecialFilesMapTreeMin(erasedNode->right, head);
      removedColor = spliceNode->color;
      fixNode = spliceNode->right;
      if (spliceNode->parent == erasedNode) {
        fixParent = spliceNode;
      } else {
        fixParent = spliceNode->parent;
        ReplaceSpecialFilesMapSubtree(*map, spliceNode, spliceNode->right);
        spliceNode->right = erasedNode->right;
        spliceNode->right->parent = spliceNode;
      }

      ReplaceSpecialFilesMapSubtree(*map, erasedNode, spliceNode);
      spliceNode->left = erasedNode->left;
      spliceNode->left->parent = spliceNode;
      spliceNode->color = erasedNode->color;
    }

    if (removedColor == kSpecialFilesMapBlack) {
      FixupSpecialFilesMapErase(*map, fixNode, fixParent);
    }

    if (head->parent != head && head->parent->isNil == 0u) {
      head->left = SpecialFilesMapTreeMin(head->parent, head);
      head->right = SpecialFilesMapTreeMax(head->parent, head);
    } else {
      head->parent = head;
      head->left = head;
      head->right = head;
    }

    DestroySpecialFilesMapNodePayload(erasedNode);
    ::operator delete(static_cast<void*>(erasedNode));
    if (map->size != 0u) {
      --map->size;
    }

    *outNextNode = next;
    return outNextNode;
  }

  /**
   * Address: 0x00849670 (FUN_00849670)
   *
   * What it does:
   * Erases one `[first,last)` range from the special-files map and returns the
   * first node that remains at the end of the erased range.
   */
  [[maybe_unused]] [[nodiscard]] SpecialFilesMapNodeRuntimeView** EraseSpecialFilesMapRange(
    SpecialFilesMapStorageRuntimeView* const map,
    SpecialFilesMapNodeRuntimeView** const outNode,
    SpecialFilesMapNodeRuntimeView* first,
    SpecialFilesMapNodeRuntimeView* const last
  )
  {
    SpecialFilesMapNodeRuntimeView* const head = map->head;
    if (first == head->left && last == head) {
      DestroySpecialFilesMapSubtree(map, head->parent);
      head->parent = head;
      map->size = 0u;
      head->left = head;
      head->right = head;
      *outNode = head->left;
      return outNode;
    }

    while (first != last && first != nullptr && first != head) {
      SpecialFilesMapNodeRuntimeView* next = first;
      (void)EraseSpecialFilesMapNodeAndAdvance(map, &next, first);
      first = next;
    }

    *outNode = first;
    return outNode;
  }

  /**
   * Address: 0x00844510 (FUN_00844510)
   *
   * What it does:
   * Releases one special-files map head allocation after erasing all nodes and
   * clears the map head/size lanes.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t ReleaseSpecialFilesMapStorage(
    SpecialFilesMapStorageRuntimeView* const map
  )
  {
    SpecialFilesMapNodeRuntimeView* cursor = nullptr;
    (void)EraseSpecialFilesMapRange(map, &cursor, map->head->left, map->head);
    ::operator delete(static_cast<void*>(map->head));
    map->head = nullptr;
    map->size = 0u;
    return 0;
  }

  struct CMauiControlLuaObjectView
  {
    std::uint8_t reserved00[0x20];
    LuaPlus::LuaObject luaObject; // +0x20

    [[nodiscard]] static CMauiControlLuaObjectView* FromControl(CMauiControl* const control) noexcept
    {
      return reinterpret_cast<CMauiControlLuaObjectView*>(control);
    }

    [[nodiscard]] static const CMauiControlLuaObjectView* FromControl(const CMauiControl* const control) noexcept
    {
      return reinterpret_cast<const CMauiControlLuaObjectView*>(control);
    }
  };
  static_assert(
    offsetof(CMauiControlLuaObjectView, luaObject) == 0x20, "CMauiControlLuaObjectView::luaObject offset must be 0x20"
  );

  struct CommandIssueWeakSetNode
  {
    CommandIssueWeakSetNode* left;   // +0x00
    CommandIssueWeakSetNode* parent; // +0x04
    CommandIssueWeakSetNode* right;  // +0x08
    std::uint32_t key;               // +0x0C
    WeakPtr<UserEntity> value;       // +0x10
    std::uint8_t color;              // +0x18
    std::uint8_t isNil;              // +0x19
    std::uint8_t pad_1A_1B[2];       // +0x1A
  };
  static_assert(sizeof(CommandIssueWeakSetNode) == 0x1C, "CommandIssueWeakSetNode size must be 0x1C");
  static_assert(offsetof(CommandIssueWeakSetNode, key) == 0x0C, "CommandIssueWeakSetNode::key offset must be 0x0C");
  static_assert(
    offsetof(CommandIssueWeakSetNode, value) == 0x10, "CommandIssueWeakSetNode::value offset must be 0x10"
  );
  static_assert(
    offsetof(CommandIssueWeakSetNode, isNil) == 0x19, "CommandIssueWeakSetNode::isNil offset must be 0x19"
  );

  struct CommandIssueWeakSetRuntimeView
  {
    void* proxy;                    // +0x00
    CommandIssueWeakSetNode* head;  // +0x04
    std::uint32_t size;             // +0x08
  };
  static_assert(sizeof(CommandIssueWeakSetRuntimeView) == 0x0C, "CommandIssueWeakSetRuntimeView size must be 0x0C");
  static_assert(
    offsetof(CommandIssueWeakSetRuntimeView, head) == 0x04, "CommandIssueWeakSetRuntimeView::head offset must be 0x04"
  );

  struct CommandIssueUpdateEventRuntimeView
  {
    CmdId commandId;                              // +0x00
    std::uint32_t eventType;                      // +0x04
    CommandIssueWeakSetRuntimeView entitySet;     // +0x08
    std::int32_t count;                           // +0x14
    CAiTarget target;                             // +0x18
    gpg::fastvector_n<SOCellPos, 2> cells;       // +0x38
  };
  static_assert(sizeof(gpg::fastvector_n<SOCellPos, 2>) == 0x18, "gpg::fastvector_n<SOCellPos,2> size must be 0x18");
  static_assert(
    offsetof(CommandIssueUpdateEventRuntimeView, commandId) == 0x00,
    "CommandIssueUpdateEventRuntimeView::commandId offset must be 0x00"
  );
  static_assert(
    offsetof(CommandIssueUpdateEventRuntimeView, eventType) == 0x04,
    "CommandIssueUpdateEventRuntimeView::eventType offset must be 0x04"
  );
  static_assert(
    offsetof(CommandIssueUpdateEventRuntimeView, entitySet) == 0x08,
    "CommandIssueUpdateEventRuntimeView::entitySet offset must be 0x08"
  );
  static_assert(
    offsetof(CommandIssueUpdateEventRuntimeView, count) == 0x14,
    "CommandIssueUpdateEventRuntimeView::count offset must be 0x14"
  );
  static_assert(
    offsetof(CommandIssueUpdateEventRuntimeView, target) == 0x18,
    "CommandIssueUpdateEventRuntimeView::target offset must be 0x18"
  );
  static_assert(
    offsetof(CommandIssueUpdateEventRuntimeView, cells) == 0x38,
    "CommandIssueUpdateEventRuntimeView::cells offset must be 0x38"
  );
  static_assert(sizeof(CommandIssueUpdateEventRuntimeView) == 0x50, "CommandIssueUpdateEventRuntimeView size must be 0x50");

  struct CommandIssueUpdateQueueRuntimeView
  {
    std::uint32_t proxy;                           // +0x00
    CommandIssueUpdateEventRuntimeView** slots;    // +0x04
    std::uint32_t capacity;                        // +0x08
    std::uint32_t readIndex;                       // +0x0C
    std::uint32_t count;                           // +0x10
  };
  static_assert(sizeof(CommandIssueUpdateQueueRuntimeView) == 0x14, "CommandIssueUpdateQueueRuntimeView size must be 0x14");
  static_assert(
    offsetof(CommandIssueUpdateQueueRuntimeView, slots) == 0x04,
    "CommandIssueUpdateQueueRuntimeView::slots offset must be 0x04"
  );
  static_assert(
    offsetof(CommandIssueUpdateQueueRuntimeView, capacity) == 0x08,
    "CommandIssueUpdateQueueRuntimeView::capacity offset must be 0x08"
  );
  static_assert(
    offsetof(CommandIssueUpdateQueueRuntimeView, readIndex) == 0x0C,
    "CommandIssueUpdateQueueRuntimeView::readIndex offset must be 0x0C"
  );
  static_assert(
    offsetof(CommandIssueUpdateQueueRuntimeView, count) == 0x10,
    "CommandIssueUpdateQueueRuntimeView::count offset must be 0x10"
  );

  struct CommandIssueHelperRuntimeView
  {
    std::uint8_t pad_0000_0004[0x04];
    CmdId commandId;                                // +0x04 (mDat.mCmdId)
    std::uint8_t pad_0008_00B8[0xB0];
    CommandIssueUpdateQueueRuntimeView localQueue;  // +0xB8
  };
  static_assert(
    offsetof(CommandIssueHelperRuntimeView, commandId) == 0x04,
    "CommandIssueHelperRuntimeView::commandId offset must be 0x04"
  );
  static_assert(
    offsetof(CommandIssueHelperRuntimeView, localQueue) == 0xB8,
    "CommandIssueHelperRuntimeView::localQueue offset must be 0xB8"
  );

  static_assert(sizeof(CommandManager) == 0xCC0, "CommandManager size must be 0xCC0");

  static_assert(
    offsetof(SimSubRes3, mValue) == offsetof(BVIntSet, mFirstWordIndex), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(
    offsetof(SimSubRes3, mReserved04) == offsetof(BVIntSet, mReservedMetaWord), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(offsetof(SimSubRes3, mValues) == offsetof(BVIntSet, mWords), "SimSubRes3/BVIntSet offset mismatch");
  static_assert(sizeof(SimSubRes3) == sizeof(BVIntSet), "SimSubRes3/BVIntSet size mismatch");

  [[nodiscard]]
  BVIntSet& AsBitSet(SimSubRes3& slot) noexcept
  {
    return *reinterpret_cast<BVIntSet*>(&slot);
  }

  /**
   * Address: 0x008B5BB0 (FUN_008B5BB0, sub_8B5BB0)
   *
   * What it does:
   * Finds one command-issue helper by command id in the session command-manager
   * map and returns the mapped helper pointer, or `nullptr` when absent.
   *
   * Real disassembly (`std::map_CmdId_CommandIssueHelper::find`, FUN_008B6160,
   * cited on `rb_tree::find_node` in `RbTree.h`) is a plain
   * `commandManager->mCommands.find(cmdId)`; this used to reach in through a
   * bespoke `CommandDbMapStorageView`/`CommandDbMapNodeView` pair
   * (`CommandIssueMapOf` + `FindCommandNode`) that hand-walked the same real
   * `msvc8::map<CmdId, UserCommandIssueHelper*> CommandManager::mCommands`
   * (`CommandManager.h`) member instead of calling it.
   */
  [[nodiscard]] CommandIssueHelperRuntimeView* FindCommandIssueHelperInManager(
    CommandManager* const commandManager,
    const CmdId cmdId
  ) noexcept
  {
    if (commandManager == nullptr) {
      return nullptr;
    }

    const auto it = commandManager->mCommands.find(cmdId);
    if (it == commandManager->mCommands.end()) {
      return nullptr;
    }

    return reinterpret_cast<CommandIssueHelperRuntimeView*>(it->second);
  }

  [[nodiscard]] CommandIssueHelperRuntimeView* FindCommandIssueHelper(CWldSession* const session, const CmdId cmdId)
  {
    if (!session || !session->mCommandManager) {
      return nullptr;
    }

    CommandManager* const commandManager = session->mCommandManager;
    return FindCommandIssueHelperInManager(commandManager, cmdId);
  }

  /**
   * Address: 0x008B5B50 (FUN_008B5B50, struct_CommandManager::NextCmdId)
   *
   * What it does:
   * Allocates one next command low-id from the manager id-pool (released set
   * first, then sequential cursor), packs the active source byte into high bits,
   * and writes the resulting command id to `outCommandId`.
   */
  [[nodiscard]] std::uint32_t* AllocatePackedCommandIdFromManager(
    CommandManager* const commandManager,
    std::uint32_t* const outCommandId
  ) noexcept
  {
    if (commandManager->mSourceId == 0xFFu) {
      *outCommandId = std::numeric_limits<std::uint32_t>::max();
      return outCommandId;
    }

    std::uint32_t nextLowId = 0u;
    if (commandManager->mIdPool.mReleasedLows.mWords.begin() == commandManager->mIdPool.mReleasedLows.mWords.end()) {
      nextLowId = static_cast<std::uint32_t>(commandManager->mIdPool.mNextLowId++);
    } else {
      nextLowId = commandManager->mIdPool.mReleasedLows.GetNext(std::numeric_limits<std::uint32_t>::max());
      (void)commandManager->mIdPool.mReleasedLows.Remove(nextLowId);
    }

    *outCommandId = nextLowId | (static_cast<std::uint32_t>(commandManager->mSourceId) << 24u);
    return outCommandId;
  }

  constexpr std::uint32_t kCommandIssueUpdateEventTypeIncreaseCount = 1u;
  constexpr std::uint32_t kCommandIssueUpdateEventTypeDecreaseCount = 2u;
  constexpr std::uint8_t kCommandIssueTreeBlack = 1u;
  constexpr std::uint32_t kCommandIssueQueueMaxCapacity = 53687091u;

  /**
   * Address: 0x008B5410 (FUN_008B5410, sub_8B5410)
   *
   * IDA signature:
   * void __noreturn sub_8B5410();
   *
   * What it does:
   * MSVC8 std::deque<T>::_Xlen for the command-issue update ring: throws
   * std::length_error("deque<T> too long") when the block map would exceed its
   * maximum size (kCommandIssueQueueMaxCapacity). Never returns.
   */
  [[noreturn]] void ThrowCommandIssueQueueTooLong()
  {
    throw std::length_error("deque<T> too long");
  }

  /**
   * Address: 0x008B5690 (FUN_008B5690, sub_8B5690)
   *
   * IDA signature:
   * void *__fastcall sub_8B5690(unsigned int a1);
   *
   * What it does:
   * MSVC8 std::allocator<CommandIssueUpdateEventRuntimeView*>::allocate for the
   * command-issue ring's block map: rejects an element count that would overflow
   * the byte size (0xFFFFFFFF / n < 4) by throwing std::bad_alloc, otherwise
   * returns operator new(4 * n) raw storage for `n` slot pointers.
   */
  [[nodiscard]] CommandIssueUpdateEventRuntimeView** AllocateCommandIssueUpdateMap(std::uint32_t slotCount)
  {
    if (0xFFFFFFFFu / slotCount < sizeof(CommandIssueUpdateEventRuntimeView*)) {
      throw std::bad_alloc();
    }
    return static_cast<CommandIssueUpdateEventRuntimeView**>(
      ::operator new(sizeof(CommandIssueUpdateEventRuntimeView*) * static_cast<std::size_t>(slotCount)));
  }

  [[nodiscard]] CommandIssueWeakSetNode* AllocateCommandIssueWeakSetHead()
  {
    auto* const head = static_cast<CommandIssueWeakSetNode*>(::operator new(sizeof(CommandIssueWeakSetNode)));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->key = 0u;
    head->value.ownerLinkSlot = nullptr;
    head->value.nextInOwner = nullptr;
    head->color = kCommandIssueTreeBlack;
    head->isNil = 1u;
    head->pad_1A_1B[0] = 0u;
    head->pad_1A_1B[1] = 0u;
    return head;
  }

  void InitializeCommandIssueWeakSetEmpty(CommandIssueWeakSetRuntimeView& set)
  {
    set.proxy = nullptr;
    set.head = AllocateCommandIssueWeakSetHead();
    set.size = 0u;
  }

  [[nodiscard]] CommandIssueWeakSetNode*
  CommandIssueWeakSetMinNode(CommandIssueWeakSetNode* node, CommandIssueWeakSetNode* const head) noexcept
  {
    while (node->left != head) {
      node = node->left;
    }
    return node;
  }

  [[nodiscard]] CommandIssueWeakSetNode*
  CommandIssueWeakSetMaxNode(CommandIssueWeakSetNode* node, CommandIssueWeakSetNode* const head) noexcept
  {
    while (node->right != head) {
      node = node->right;
    }
    return node;
  }

  void DestroyCommandIssueWeakSetNodes(CommandIssueWeakSetNode* const node, CommandIssueWeakSetNode* const head)
  {
    if (node == nullptr || node == head) {
      return;
    }

    DestroyCommandIssueWeakSetNodes(node->left, head);
    DestroyCommandIssueWeakSetNodes(node->right, head);
    node->value.ResetFromObject(nullptr);
    ::operator delete(node);
  }

  void DestroyCommandIssueWeakSet(CommandIssueWeakSetRuntimeView& set)
  {
    if (set.head == nullptr) {
      set.proxy = nullptr;
      set.size = 0u;
      return;
    }

    if (set.head->parent != set.head) {
      DestroyCommandIssueWeakSetNodes(set.head->parent, set.head);
    }

    ::operator delete(set.head);
    set.proxy = nullptr;
    set.head = nullptr;
    set.size = 0u;
  }

  [[nodiscard]] CommandIssueWeakSetNode* CloneCommandIssueWeakSetNode(
    const CommandIssueWeakSetNode* const sourceNode,
    const CommandIssueWeakSetNode* const sourceHead,
    CommandIssueWeakSetNode* const destinationHead,
    CommandIssueWeakSetNode* const parent
  )
  {
    if (sourceNode == nullptr || sourceNode == sourceHead) {
      return destinationHead;
    }

    auto* const destinationNode = static_cast<CommandIssueWeakSetNode*>(::operator new(sizeof(CommandIssueWeakSetNode)));
    destinationNode->left = destinationHead;
    destinationNode->parent = parent;
    destinationNode->right = destinationHead;
    destinationNode->key = sourceNode->key;
    destinationNode->value.ownerLinkSlot = nullptr;
    destinationNode->value.nextInOwner = nullptr;
    destinationNode->value.ResetFromOwnerLinkSlot(sourceNode->value.ownerLinkSlot);
    destinationNode->color = sourceNode->color;
    destinationNode->isNil = sourceNode->isNil;
    destinationNode->pad_1A_1B[0] = sourceNode->pad_1A_1B[0];
    destinationNode->pad_1A_1B[1] = sourceNode->pad_1A_1B[1];

    destinationNode->left =
      CloneCommandIssueWeakSetNode(sourceNode->left, sourceHead, destinationHead, destinationNode);
    destinationNode->right =
      CloneCommandIssueWeakSetNode(sourceNode->right, sourceHead, destinationHead, destinationNode);
    return destinationNode;
  }

  void CopyCommandIssueWeakSet(
    CommandIssueWeakSetRuntimeView& destination,
    const CommandIssueWeakSetRuntimeView& source
  )
  {
    if (&destination == &source) {
      return;
    }

    DestroyCommandIssueWeakSet(destination);
    destination.proxy = source.proxy;
    if (source.head == nullptr) {
      destination.head = nullptr;
      destination.size = 0u;
      return;
    }

    destination.head = AllocateCommandIssueWeakSetHead();
    destination.size = source.size;
    if (source.head->parent == source.head || source.size == 0u) {
      destination.head->left = destination.head;
      destination.head->parent = destination.head;
      destination.head->right = destination.head;
      return;
    }

    destination.head->parent = CloneCommandIssueWeakSetNode(
      source.head->parent,
      source.head,
      destination.head,
      destination.head
    );
    destination.head->parent->parent = destination.head;
    destination.head->left = CommandIssueWeakSetMinNode(destination.head->parent, destination.head);
    destination.head->right = CommandIssueWeakSetMaxNode(destination.head->parent, destination.head);
  }

  void InitializeCommandIssueTarget(CAiTarget& target)
  {
    target.targetType = EAiTargetType::AITARGET_None;
    target.targetEntity.ResetFromObject(nullptr);
    target.position = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    target.targetPoint = 0;
    target.targetIsMobile = false;
  }

  /**
   * Address: 0x008B3DC0 (FUN_008B3DC0, sub_8B3DC0)
   *
   * What it does:
   * Initializes one command-issue local queue event with command id, event type,
   * empty weak-set payload, empty target payload, and inline cell-vector lanes.
   */
  void InitializeCommandIssueUpdateEvent(
    CommandIssueUpdateEventRuntimeView& event,
    const CmdId commandId,
    const std::uint32_t eventType
  )
  {
    event.commandId = commandId;
    event.eventType = eventType;
    InitializeCommandIssueWeakSetEmpty(event.entitySet);
    event.count = 0;
    InitializeCommandIssueTarget(event.target);
    gpg::FastVectorN2InitInlineNoHeader(event.cells);
  }

  void DestroyCommandIssueUpdateEvent(CommandIssueUpdateEventRuntimeView& event)
  {
    event.target.targetEntity.ResetFromObject(nullptr);
    event.cells.ResetStorageToInline();
    DestroyCommandIssueWeakSet(event.entitySet);
  }

  /**
   * Address: 0x008B56F0 (FUN_008B56F0, sub_8B56F0)
   *
   * What it does:
   * Copy-constructs one command-issue local queue event: command id and event
   * type by value, the weak-set entity payload via CopyCommandIssueWeakSet,
   * count, target, and the inline cell-vector lanes via
   * gpg::FastVectorN2RebindAndCopy. Reached unconditionally from
   * EnqueueCommandIssueUpdateEvent (0x008B4E80) once that function has
   * already guaranteed the destination slot is non-null -- the binary's
   * sub_8B52C0 null-check wrapper around this body is therefore always-true
   * at its only real call site and is correctly elided here rather than
   * modeled as a separate function.
   */
  void CopyCommandIssueUpdateEvent(
    CommandIssueUpdateEventRuntimeView& destination,
    const CommandIssueUpdateEventRuntimeView& source
  )
  {
    if (&destination == &source) {
      return;
    }

    destination.commandId = source.commandId;
    destination.eventType = source.eventType;
    CopyCommandIssueWeakSet(destination.entitySet, source.entitySet);
    destination.count = source.count;
    destination.target = source.target;
    destination.target.targetPoint = source.target.targetPoint;
    destination.cells.ResetStorageToInline();
    gpg::FastVectorN2RebindAndCopy<SOCellPos>(&destination.cells, &source.cells);
  }

  /**
   * Address: 0x008B55D0 (FUN_008B55D0, checked allocator for
   * CommandIssueUpdateEventRuntimeView, elementSize=0x50, reached from
   * EnqueueCommandIssueUpdateEvent via this function)
   *
   * The binary routes the allocation through a checked `_Allocate(count,
   * elementSize)`-shaped wrapper (`0xFFFFFFFF/count < 0x50` throws
   * `std::bad_alloc`, else `operator new(0x50*count)`) called with count=1;
   * for a hardcoded count of 1 this is behaviorally identical to the plain
   * `::operator new` below (the guard cannot be reached), so no separate
   * checked-allocator call is introduced here.
   */
  [[nodiscard]] CommandIssueUpdateEventRuntimeView* AllocateCommandIssueUpdateSlot()
  {
    auto* const storage = static_cast<CommandIssueUpdateEventRuntimeView*>(::operator new(sizeof(CommandIssueUpdateEventRuntimeView)));
    new (storage) CommandIssueUpdateEventRuntimeView{};
    InitializeCommandIssueUpdateEvent(*storage, 0, 0u);
    return storage;
  }

  /**
   * Address: 0x008B50A0 (FUN_008B50A0, sub_8B50A0)
   *
   * IDA signature:
   * char *__usercall sub_8B50A0@<eax>(int this@<esi>);  // this = deque map struct
   *
   * What it does:
   * MSVC8 std::deque<CommandIssueUpdateEventRuntimeView>::_Growmap for the
   * command-issue helper's local ring (block size 1). Enlarges the block-pointer
   * map by growth = clamp(oldCapacity/2, min 8) capped so oldCapacity+growth does
   * not exceed kCommandIssueQueueMaxCapacity (throws std::length_error otherwise).
   * Allocates a new map (checked allocator, or bare operator new when the new size
   * is 0), then relocates the wrapped contents preserving the ABSOLUTE readIndex
   * (_Myoff) position: the tail [readIndex..oldCapacity) stays in place; the front
   * segment [0..readIndex) is split across the newly-added high slots and the low
   * slots depending on whether readIndex <= growth, with the vacated slots zeroed.
   * Frees the old map, then sets capacity += growth and slots = newMap. readIndex
   * and count are left unchanged. Returns the new map (caller ignores the result).
   */
  CommandIssueUpdateEventRuntimeView** GrowCommandIssueUpdateQueue(CommandIssueUpdateQueueRuntimeView& queue)
  {
    const std::uint32_t oldCapacity = queue.capacity;

    // deque map-size overflow guard (0x3333333 - mapsize < 1 == mapsize maxed out).
    if ((kCommandIssueQueueMaxCapacity - oldCapacity) < 1u) {
      ThrowCommandIssueQueueTooLong();
    }

    std::uint32_t growth = 1u;
    std::uint32_t halfCapacity = oldCapacity >> 1u;
    if (halfCapacity < 8u) {
      halfCapacity = 8u;
    }
    if (oldCapacity <= (kCommandIssueQueueMaxCapacity - halfCapacity)) {
      growth = halfCapacity;
    }

    const std::uint32_t newCapacity = oldCapacity + growth;
    const std::uint32_t readIndex = queue.readIndex;

    CommandIssueUpdateEventRuntimeView** const newSlots =
      (newCapacity != 0u)
        ? AllocateCommandIssueUpdateMap(newCapacity)
        : static_cast<CommandIssueUpdateEventRuntimeView**>(::operator new(0));

    constexpr std::size_t slotBytes = sizeof(CommandIssueUpdateEventRuntimeView*);
    CommandIssueUpdateEventRuntimeView** const oldSlots = queue.slots;

    // Tail: new[readIndex..oldCapacity) = old[readIndex..oldCapacity).
    const std::uint32_t tailCount = oldCapacity - readIndex;
    if (tailCount != 0u) {
      ::memmove_s(newSlots + readIndex, tailCount * slotBytes,
                  oldSlots + readIndex, tailCount * slotBytes);
    }

    if (readIndex > growth) {
      // Front [0..readIndex) wraps past the newly added slots.
      // Head-copy: new[oldCapacity..oldCapacity+growth) = old[0..growth).
      if (growth != 0u) {
        ::memmove_s(newSlots + oldCapacity, growth * slotBytes,
                    oldSlots, growth * slotBytes);
      }
      // Mid-copy: new[0..readIndex-growth) = old[growth..readIndex).
      const std::uint32_t midCount = readIndex - growth;
      if (midCount != 0u) {
        ::memmove_s(newSlots, midCount * slotBytes,
                    oldSlots + growth, midCount * slotBytes);
      }
      // Zero the slots vacated by the wrap: new[readIndex-growth..readIndex).
      if (growth != 0u) {
        std::memset(newSlots + (readIndex - growth), 0, growth * slotBytes);
      }
    } else {
      // Front fits within the added slots.
      // Head-copy: new[oldCapacity..oldCapacity+readIndex) = old[0..readIndex).
      if (readIndex != 0u) {
        ::memmove_s(newSlots + oldCapacity, readIndex * slotBytes,
                    oldSlots, readIndex * slotBytes);
      }
      // Zero the freshly grown remainder: new[oldCapacity+readIndex..newCapacity).
      if (growth != readIndex) {
        std::memset(newSlots + (oldCapacity + readIndex), 0,
                    (growth - readIndex) * slotBytes);
      }
      // Zero the low slots the front vacated: new[0..readIndex).
      if (readIndex != 0u) {
        std::memset(newSlots, 0, readIndex * slotBytes);
      }
    }

    if (oldSlots != nullptr) {
      ::operator delete(oldSlots);
    }

    queue.capacity = oldCapacity + growth;
    queue.slots = newSlots;
    return newSlots;
  }

  /**
   * Address: 0x008B4E80 (FUN_008B4E80, sub_8B4E80)
   *
   * What it does:
   * Enqueues one local command-issue update event into the helper ring queue,
   * growing slot storage and slot-event storage on demand.
   */
  void EnqueueCommandIssueUpdateEvent(
    CommandIssueUpdateQueueRuntimeView& queue,
    const CommandIssueUpdateEventRuntimeView& event
  )
  {
    if (queue.capacity <= (queue.count + 1u)) {
      GrowCommandIssueUpdateQueue(queue);
    }

    std::uint32_t writeIndex = queue.readIndex + queue.count;
    if (writeIndex >= queue.capacity) {
      writeIndex -= queue.capacity;
    }

    if (queue.slots[writeIndex] == nullptr) {
      queue.slots[writeIndex] = AllocateCommandIssueUpdateSlot();
    }

    CopyCommandIssueUpdateEvent(*queue.slots[writeIndex], event);
    ++queue.count;
  }

  /**
   * Address: 0x008B3E50 (FUN_008B3E50, sub_8B3E50)
   *
   * What it does:
   * Relocate-copies a UI-side command target's type/entity-link/position
   * lanes (the first 0x18 bytes of `moho::UserTarget`, see
   * `UserCommandTargetView`'s own doc comment in UserUnit.h) into a sim-side
   * `CAiTarget`, relinking the destination's weak-entity chain membership to
   * the source's when they differ and leaving `targetPoint`/`targetIsMobile`
   * untouched (matches `CAiTarget::CopyFromLinkedTarget`'s own field split,
   * just against a different source type). Sole caller is `sub_8B4A40`
   * (0x008B4A68: eax=dest=localEvent+0x18, esi=source=sub_8B4A40's own 3rd
   * stack arg).
   */
  CAiTarget& CopyUserCommandTargetIntoAiTarget(
    CAiTarget& destination, const UserCommandTargetView& source
  ) noexcept
  {
    destination.targetType = static_cast<EAiTargetType>(source.targetType);
    if (reinterpret_cast<std::uintptr_t>(destination.targetEntity.ownerLinkSlot) != source.targetEntity.ownerLinkSlot) {
      destination.targetEntity.ResetFromOwnerLinkSlot(reinterpret_cast<void*>(source.targetEntity.ownerLinkSlot));
    }
    destination.position = source.position;
    return destination;
  }

  /**
   * Address: 0x008BECD0 (FUN_008BECD0, sub_8BECD0)
   *
   * What it does:
   * Converts one UI-side command target (`moho::UserTarget`, see
   * `UserCommandTargetView` in UserUnit.h) into the sim-side network payload
   * `SSTITarget`. `Entity` targets resolve the owning `UserEntity`'s stable
   * id (`SCreateEntityParams::mEntityId` at `UserEntity::mParams`, decoded
   * through the same `ownerLinkSlot - 8` weak-owner convention used
   * throughout UserUnit.cpp) or the sentinel id `0xF0000000` when the link
   * slot is null or still the empty-slot tombstone (`== 8`); `Position`
   * targets copy the inline position; any other target type maps to
   * `AITARGET_None` with the sentinel id. Sole caller is
   * `Moho::ISSUE_SetCommandTarget` (0x008B0EE0).
   */
  [[nodiscard]] SSTITarget ConvertUserCommandTargetToSSTITarget(const UserCommandTargetView& source) noexcept
  {
    constexpr std::uint32_t kUnresolvedTargetEntityId = 0xF0000000u;

    SSTITarget result{};
    if (source.targetType == UserTargetType::Entity) {
      result.mType = EAiTargetType::AITARGET_Entity;
      result.mEntityId = kUnresolvedTargetEntityId;
      if (source.targetEntity.ownerLinkSlot != 0u && source.targetEntity.ownerLinkSlot != 8u) {
        const auto* const entity =
          reinterpret_cast<const UserEntity*>(source.targetEntity.ownerLinkSlot - 8u);
        result.mEntityId = entity->mParams.mEntityId;
      }
    } else if (source.targetType == UserTargetType::Position) {
      result.mType = EAiTargetType::AITARGET_Ground;
      result.mEntityId = kUnresolvedTargetEntityId;
      result.mPos = source.position;
    } else {
      result.mType = EAiTargetType::AITARGET_None;
      result.mEntityId = kUnresolvedTargetEntityId;
    }
    return result;
  }

  // Local command-issue update event type used for "set target" events
  // (0x008B4A5F: `mov ecx, 4` feeding InitializeCommandIssueUpdateEvent).
  constexpr std::uint32_t kCommandIssueUpdateEventTypeSetTarget = 4u;

  /**
   * Address: 0x008B4A40 (FUN_008B4A40, sub_8B4A40)
   *
   * What it does:
   * Builds one local "set-target" command-issue update event (command id
   * `commandId`, target payload relocate-copied from `targetPayload` via
   * `CopyUserCommandTargetIntoAiTarget`), enqueues it into the helper's
   * local ring queue, then destroys the local event. Sole caller is
   * `Moho::ISSUE_SetCommandTarget` (0x008B0EE0).
   *
   * The destroy step calls the real `sub_8B4800` (`DestroyCommandIssueLocalEvent`,
   * UserUnit.cpp) rather than this file's own unaddressed
   * `DestroyCommandIssueUpdateEvent` symmetry helper - the binary call site
   * (0x008B4A9E) resolves to 0x008B4800 specifically. `UserCommandIssueLocalEventRuntimeView`
   * and `CommandIssueUpdateEventRuntimeView` are proven byte-compatible for
   * every field both name (see the former's doc comment in UserUnit.h), so
   * the cast below is a same-object dual-view bridge, not a layout guess.
   */
  void QueueCommandIssueSetTargetEvent(
    CommandIssueHelperRuntimeView& commandIssueHelper,
    const CmdId commandId,
    const UserCommandTargetView& targetPayload
  )
  {
    CommandIssueUpdateEventRuntimeView localEvent{};
    InitializeCommandIssueUpdateEvent(localEvent, commandId, kCommandIssueUpdateEventTypeSetTarget);
    CopyUserCommandTargetIntoAiTarget(localEvent.target, targetPayload);
    EnqueueCommandIssueUpdateEvent(commandIssueHelper.localQueue, localEvent);
    DestroyCommandIssueLocalEvent(reinterpret_cast<UserCommandIssueLocalEventRuntimeView&>(localEvent));
  }

  /**
   * Address: 0x008B0EE0 (FUN_008B0EE0, ?ISSUE_SetCommandTarget@Moho@@YAXPAVUserCommand@1@ABVUserTarget@1@@Z)
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_SetCommandTarget(Moho::UserCommand* helper, Moho::UserTarget const& target);
   *
   * What it does:
   * Client/UI-side command-target keystone, the `ISSUE_Command` family's
   * counterpart for redirecting a command already in flight. Resolves the
   * target's world position and gates it against the same no-rush timer/
   * radius rule `ISSUE_Command` applies (skipped outright when the target is
   * `None`, or when the resolved position is invalid/no focus army is set);
   * once past the gate (or bypassed via an invalid position/focus army),
   * further gates on the helper's own command type: when it is not the
   * pickup-style type (raw ordinal `22`; no named `EUnitCommandType`
   * enumerator has been recovered for it yet), the retarget always proceeds.
   * When it is that type, the retarget proceeds only if the target resolves
   * to a live entity in one of `FERRYBEACON`/`TRANSPORTATION`/
   * `AIRSTAGINGPLATFORM` - any other entity (or a non-entity target) is
   * silently rejected. On proceed: converts the target to `SSTITarget` and
   * publishes it through the active sim driver, then queues the matching
   * local "set-target" update event via `QueueCommandIssueSetTargetEvent`.
   */
  void ISSUE_SetCommandTarget(UserCommandIssueHelper* const helper, const UserCommandTargetView& target)
  {
    auto& helperView = reinterpret_cast<CommandIssueHelperRuntimeView&>(*helper);

    CWldSession* const session = WLD_GetActiveSession();
    auto* const playableMap = reinterpret_cast<STIMap*>(session->mWldMap->mTerrainRes->mPlayableRectSource);

    bool shouldRetarget = (target.targetType == UserTargetType::None);
    if (!shouldRetarget) {
      const Wm3::Vector3<float> targetPosition = ResolvePositionFromTarget(target);
      if (!IsValidVector3f(targetPosition)) {
        shouldRetarget = true;
      } else if (session->FocusArmy >= 0) {
        if (UserArmy* const focusArmyByIndex = session->userArmies[static_cast<std::size_t>(session->FocusArmy)];
            focusArmyByIndex != nullptr) {
          const bool insidePlayableArea = focusArmyByIndex->mVarDat.mUseWholeMap != 0u || playableMap == nullptr ||
            playableMap->IsPlayable(targetPosition);
          if (insidePlayableArea) {
            const UserArmy* const focusArmy = session->GetFocusArmy();
            if (focusArmy->mVarDat.mNoRushTimer <= 0) {
              shouldRetarget = true;
            } else {
              const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPosition.x;
              const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPosition.z;
              const float distance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
              shouldRetarget = (distance <= focusArmy->mVarDat.mNoRushRadius);
            }
          }
        }
      }
    }

    if (!shouldRetarget) {
      return;
    }

    // Command-type gate: only the pickup-style command type (raw ordinal 22;
    // see this function's own doc comment) restricts retargeting to a live
    // entity in one of the three transport-ish categories below. Every other
    // command type retargets unconditionally.
    if (ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(22)) {
      if (target.targetType == UserTargetType::Entity && target.targetEntity.ownerLinkSlot != 0u &&
          target.targetEntity.ownerLinkSlot != 8u) {
        UserEntity* const targetEntity = DecodeEntityFromCommandTargetIfEntity(&target);
        const bool isEligibleEntity = targetEntity->IsInCategory(msvc8::string("FERRYBEACON", 11u)) ||
          targetEntity->IsInCategory(msvc8::string("TRANSPORTATION", 14u)) ||
          targetEntity->IsInCategory(msvc8::string("AIRSTAGINGPLATFORM", 18u));
        if (!isEligibleEntity) {
          return;
        }
      }
      // Entity link is null/tombstone, or the target isn't an Entity at all:
      // the binary falls out of the `if (*a2 == 1)`/`if (v8)`/`if (v8)` chain
      // without ever reaching the category checks or the reject, i.e. it
      // reaches the end of the function without dispatching either.
      else {
        return;
      }
    }

    if (ISTIDriver* const simDriver = SIM_GetActiveDriver()) {
      simDriver->SetCommandTarget(helperView.commandId, ConvertUserCommandTargetToSSTITarget(target));
    }
    QueueCommandIssueSetTargetEvent(helperView, helperView.commandId, target);
  }

  // Local command-issue update event type used for "set command type" events
  // (0x008B4AE3: `mov ecx, 5` feeding InitializeCommandIssueUpdateEvent).
  constexpr std::uint32_t kCommandIssueUpdateEventTypeSetType = 5u;

  /**
   * Address: 0x008B4AC0 (FUN_008B4AC0, sub_8B4AC0)
   *
   * IDA signature:
   * void __stdcall sub_8B4AC0(int arg0, int a2, int a3);
   *
   * What it does:
   * Builds one local "set-type" command-issue update event (command id
   * `commandId`), packs `newCommandType` into the target payload's
   * `targetPoint` slot (0x008B4AF8: `mov [eax+30h], ecx` - the same
   * union-style tag-data reuse `QueueCommandIssueSetTargetEvent`'s sibling
   * events use for their own payload data), enqueues it into the helper's
   * local ring queue, then destroys the local event. Sole caller is
   * `Moho::ReissueCommandIssueEntryAsType` below.
   */
  void QueueCommandIssueSetTypeEvent(
    CommandIssueHelperRuntimeView& commandIssueHelper,
    const CmdId commandId,
    const EUnitCommandType newCommandType
  )
  {
    CommandIssueUpdateEventRuntimeView localEvent{};
    InitializeCommandIssueUpdateEvent(localEvent, commandId, kCommandIssueUpdateEventTypeSetType);
    localEvent.target.targetPoint = static_cast<std::int32_t>(newCommandType);
    EnqueueCommandIssueUpdateEvent(commandIssueHelper.localQueue, localEvent);
    DestroyCommandIssueLocalEvent(reinterpret_cast<UserCommandIssueLocalEventRuntimeView&>(localEvent));
  }

  /**
   * Address: 0x008B4960 (FUN_008B4960, sub_8B4960)
   *
   * What it does:
   * Builds one `IncreaseCommandCount` local update event and appends it into
   * the command-issue helper's local ring queue.
   */
  [[maybe_unused]] void QueueCommandIssueIncreaseCountEvent(
    CommandIssueHelperRuntimeView& commandIssueHelper,
    const CmdId commandId,
    const std::int32_t deltaCount
  )
  {
    CommandIssueUpdateEventRuntimeView localEvent{};
    InitializeCommandIssueUpdateEvent(localEvent, commandId, kCommandIssueUpdateEventTypeIncreaseCount);
    localEvent.count = deltaCount;
    EnqueueCommandIssueUpdateEvent(commandIssueHelper.localQueue, localEvent);
    DestroyCommandIssueUpdateEvent(localEvent);
  }

  /**
   * Address: 0x008B49D0 (FUN_008B49D0, sub_8B49D0)
   *
   * What it does:
   * Builds one `DecreaseCommandCount` local update event and appends it into
   * the command-issue helper's local ring queue.
   */
  void QueueCommandIssueDecreaseCountEvent(
    CommandIssueHelperRuntimeView& commandIssueHelper,
    const CmdId commandId,
    const std::int32_t deltaCount
  )
  {
    CommandIssueUpdateEventRuntimeView localEvent{};
    InitializeCommandIssueUpdateEvent(localEvent, commandId, kCommandIssueUpdateEventTypeDecreaseCount);
    localEvent.count = deltaCount;
    EnqueueCommandIssueUpdateEvent(commandIssueHelper.localQueue, localEvent);
    DestroyCommandIssueUpdateEvent(localEvent);
  }

  // Local command-issue update event type used for "select this unit" events
  // (the ring's default event kind whose weak set `WeakSet<UserUnit>::Add` fills).
  constexpr std::uint32_t kCommandIssueUpdateEventTypeSelectUnit = 0u;

  // Computes the ring index of the most-recently-enqueued (last) event.
  // Binary form (0x008B474D-0x008B4762): index = readIndex + count - 1, with a
  // single-step wrap when it reaches/exceeds the ring capacity.
  [[nodiscard]] std::uint32_t LastCommandIssueEventIndex(const CommandIssueUpdateQueueRuntimeView& queue)
  {
    std::uint32_t index = queue.readIndex + queue.count - 1u;
    if (queue.capacity <= index) {
      index -= queue.capacity;
    }
    return index;
  }

  /**
   * Address: 0x008B4720 (FUN_008B4720, sub_8B4720)
   *
   * IDA signature:
   * int __userpurge sub_8B4720@<eax>(_DWORD *ebx0@<ebx>, int a2, unsigned int a3);
   *   ebx = UserCommandIssueHelper*, a2 = CmdId, a3 = UserUnit*
   *
   * What it does:
   * Appends a "select unit" local update event into the helper's local ring
   * queue when the queue is empty, or when the last event is not already a
   * select-event (eventType != 0) for this command id, then inserts `unit`
   * into that last event's weak-set. The freshly-built temp event is created
   * via InitializeCommandIssueUpdateEvent, enqueued (deep-copied into the ring)
   * via EnqueueCommandIssueUpdateEvent, and torn down via
   * DestroyCommandIssueUpdateEvent; the binary wraps that teardown in an SEH
   * frame so the temp is released on both the normal and throwing paths, which
   * is modeled here with an RAII scope guard.
   */
  void QueueCommandIssueSelectUnitEventImpl(
    UserCommandIssueHelper& helper,
    const CmdId commandId,
    UserUnit* const unit
  )
  {
    auto& helperView = reinterpret_cast<CommandIssueHelperRuntimeView&>(helper);
    CommandIssueUpdateQueueRuntimeView& queue = helperView.localQueue;

    bool needNewEvent = true;
    if (queue.count != 0u) {
      const CommandIssueUpdateEventRuntimeView* const lastEvent = queue.slots[LastCommandIssueEventIndex(queue)];
      if (lastEvent->eventType == kCommandIssueUpdateEventTypeSelectUnit && lastEvent->commandId == commandId) {
        needNewEvent = false;
      }
    }

    if (needNewEvent) {
      CommandIssueUpdateEventRuntimeView localEvent{};
      InitializeCommandIssueUpdateEvent(localEvent, commandId, kCommandIssueUpdateEventTypeSelectUnit);
      struct LocalEventScopeGuard
      {
        CommandIssueUpdateEventRuntimeView* event;
        ~LocalEventScopeGuard() { DestroyCommandIssueUpdateEvent(*event); }
      } guard{&localEvent};
      EnqueueCommandIssueUpdateEvent(queue, localEvent);
    }

    CommandIssueUpdateEventRuntimeView* const lastEvent = queue.slots[LastCommandIssueEventIndex(queue)];
    // entitySet is the 0x0C {proxy, head@+4, size} weak-set at event+0x08 - the
    // same `WeakSet<UserUnit>` header `WeakSet<UserUnit>::Add` (0x00822270)
    // takes, which is why the binary reaches it here with no adjustment at all.
    WeakUnitSetUserUnit::AddResult selectedUnitAdd{};
    (void)WeakUnitSetUserUnit::Add(
      &selectedUnitAdd, reinterpret_cast<WeakUnitSetUserUnit*>(&lastEvent->entitySet), unit
    );
  }

  // Local command-issue update event type used for "deselect unit" events
  // (0x008B48F1: `mov ecx, 3` feeding InitializeCommandIssueUpdateEvent) -
  // the DeselectUnit complement of kCommandIssueUpdateEventTypeSelectUnit.
  constexpr std::uint32_t kCommandIssueUpdateEventTypeDeselectUnit = 3u;

  /**
   * Address: 0x008B4880 (FUN_008B4880, sub_8B4880)
   *
   * What it does:
   * Structural mirror of QueueCommandIssueSelectUnitEventImpl (FUN_008B4720)
   * with eventType=3 instead of 0: appends a "deselect unit" local update
   * event into the helper's local ring queue when the queue is empty, or
   * when the last event is not already a deselect-event (eventType != 3)
   * for this command id, then inserts `unit` into that last event's
   * weak-set. Unlike its select-unit sibling, the binary's own rebuild path
   * (0x008B491D) tears the temporary down through the real
   * `DestroyCommandIssueLocalEvent` (0x008B4800, UserUnit.h) rather than
   * this file's own `DestroyCommandIssueUpdateEvent` symmetry helper -
   * matched here exactly like `QueueCommandIssueSetTargetEvent` does for
   * the same reason.
   */
  void QueueCommandIssueDeselectUnitEventImpl(
    UserCommandIssueHelper& helper,
    const CmdId commandId,
    UserUnit* const unit
  )
  {
    auto& helperView = reinterpret_cast<CommandIssueHelperRuntimeView&>(helper);
    CommandIssueUpdateQueueRuntimeView& queue = helperView.localQueue;

    bool needNewEvent = true;
    if (queue.count != 0u) {
      const CommandIssueUpdateEventRuntimeView* const lastEvent = queue.slots[LastCommandIssueEventIndex(queue)];
      if (lastEvent->eventType == kCommandIssueUpdateEventTypeDeselectUnit && lastEvent->commandId == commandId) {
        needNewEvent = false;
      }
    }

    if (needNewEvent) {
      CommandIssueUpdateEventRuntimeView localEvent{};
      InitializeCommandIssueUpdateEvent(localEvent, commandId, kCommandIssueUpdateEventTypeDeselectUnit);
      EnqueueCommandIssueUpdateEvent(queue, localEvent);
      DestroyCommandIssueLocalEvent(reinterpret_cast<UserCommandIssueLocalEventRuntimeView&>(localEvent));
    }

    CommandIssueUpdateEventRuntimeView* const lastEvent = queue.slots[LastCommandIssueEventIndex(queue)];
    WeakUnitSetUserUnit::AddResult deselectedUnitAdd{};
    (void)WeakUnitSetUserUnit::Add(
      &deselectedUnitAdd, reinterpret_cast<WeakUnitSetUserUnit*>(&lastEvent->entitySet), unit
    );
  }

  CUnitCommand* FindCommandById(CCommandDb* commandDb, const CmdId cmdId)
  {
    if (!commandDb || !commandDb->commands.header_ptr()) {
      return nullptr;
    }

    auto it = commandDb->commands.find(cmdId);
    if (it == commandDb->commands.end()) {
      return nullptr;
    }

    // The map's mapped type is a CUnitCommand pointer, not a value: the binary's
    // node is {left,parent,right,key@0x0C,CUnitCommand*@0x10,color@0x14,isNil@0x15}
    // (see CommandDbMapNodeRuntime in CCommandDb.cpp), so the stored slot is
    // already the command pointer.
    return it->second;
  }

  struct EntityDbEntityMapView
  {
    void* allocatorProxy;           // +0x00
    CEntityDbAllUnitsNode* head;    // +0x04
    std::uint32_t size;             // +0x08
  };
  static_assert(offsetof(EntityDbEntityMapView, head) == 0x04, "EntityDbEntityMapView::head offset must be 0x04");
  static_assert(offsetof(EntityDbEntityMapView, size) == 0x08, "EntityDbEntityMapView::size offset must be 0x08");
  static_assert(sizeof(EntityDbEntityMapView) == 0x0C, "EntityDbEntityMapView size must be 0x0C");

  [[nodiscard]] EntityDbEntityMapView& GetEntityDbEntityMapView(CEntityDb* const entityDb) noexcept
  {
    return *reinterpret_cast<EntityDbEntityMapView*>(entityDb);
  }

  /**
   * Address: 0x006856C0 (FUN_006856C0, std::map_EntId_Entity::find)
   *
   * What it does:
   * Returns the exact entity-id tree node when present, otherwise the map
   * sentinel/head node.
   */
  [[nodiscard]] CEntityDbAllUnitsNode* FindEntityMapNode(EntityDbEntityMapView& map, const EntId id) noexcept
  {
    CEntityDbAllUnitsNode* const head = map.head;
    if (head == nullptr) {
      return nullptr;
    }

    const std::uint32_t key = static_cast<std::uint32_t>(id);
    CEntityDbAllUnitsNode* result = head;
    CEntityDbAllUnitsNode* node = head->parent;
    while (node != nullptr && node != head && node->isNil == 0u) {
      if (node->key >= key) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    if (result == head || key < result->key) {
      return head;
    }

    return result;
  }

  Entity* FindEntityById(CEntityDb* entityDb, const EntId id)
  {
    if (!entityDb) {
      return nullptr;
    }

    EntityDbEntityMapView& entityMap = GetEntityDbEntityMapView(entityDb);
    CEntityDbAllUnitsNode* const node = FindEntityMapNode(entityMap, id);
    if (node == nullptr || node == entityMap.head || node->unitListNode == nullptr) {
      return nullptr;
    }

    return static_cast<Entity*>(node->unitListNode);
  }

  static_assert(sizeof(SEntitySetTemplateUnit) == 0x28, "SEntitySetTemplateUnit size must be 0x28");
  static_assert(
    sizeof(TDatList<SEntitySetTemplateUnit, void>) == 0x08, "SEntitySetTemplateUnit link-node size must be 0x08"
  );

  void InitSimDebugEntitySet(SEntitySetTemplateUnit& outSet)
  {
    outSet.mNext = &outSet;
    outSet.mPrev = &outSet;
    outSet.mVec.RebindInlineNoFree();
  }

  void DestroySimDebugEntitySet(SEntitySetTemplateUnit& set)
  {
    set.mVec.ResetStorageToInline();

    if (set.mNext != nullptr && set.mPrev != nullptr) {
      set.ListUnlink();
      return;
    }

    set.mNext = &set;
    set.mPrev = &set;
  }

  CSimConCommand* FindSimConCommand(const std::string& commandName)
  {
    return moho::FindRegisteredSimConCommand(commandName);
  }

  [[nodiscard]]
  bool IsSimCommandWhitespace(const char ch) noexcept
  {
    return gpg::STR_IsAsciiWhitespace(ch);
  }

  enum class SimCommandTerminator
  {
    None,
    NextCommand,
    Comment,
  };

  void ParseOneSimCommand(const std::string& input, std::vector<std::string>& outTokens, std::string& outRemainder)
  {
    outTokens.clear();
    outRemainder.clear();

    std::string token;
    token.reserve(input.size());

    bool inQuotes = false;
    bool escaping = false;
    SimCommandTerminator terminator = SimCommandTerminator::None;
    std::size_t splitIndex = input.size();

    for (std::size_t i = 0; i < input.size(); ++i) {
      const char ch = input[i];

      if (escaping) {
        token.push_back(ch);
        escaping = false;
        continue;
      }

      if (inQuotes && ch == '\\') {
        escaping = true;
        continue;
      }

      if (ch == '"') {
        inQuotes = !inQuotes;
        continue;
      }

      if (!inQuotes && ch == ';') {
        terminator = SimCommandTerminator::NextCommand;
        splitIndex = i;
        break;
      }

      if (!inQuotes && ch == '#') {
        terminator = SimCommandTerminator::Comment;
        splitIndex = i;
        break;
      }

      if (!inQuotes && IsSimCommandWhitespace(ch)) {
        if (!token.empty()) {
          outTokens.push_back(token);
          token.clear();
        }
        continue;
      }

      token.push_back(ch);
    }

    if (escaping) {
      token.push_back('\\');
    }

    if (!token.empty()) {
      outTokens.push_back(token);
    }

    if (terminator == SimCommandTerminator::NextCommand && splitIndex + 1u <= input.size()) {
      outRemainder.assign(input, splitIndex + 1u, std::string::npos);
      return;
    }

    outRemainder.clear();
  }

  [[nodiscard]]
  bool SimCommandTokenNeedsQuotes(const std::string& token)
  {
    if (token.empty()) {
      return true;
    }

    for (const char ch : token) {
      if (IsSimCommandWhitespace(ch) || ch == ';' || ch == '#') {
        return true;
      }
    }

    return false;
  }

  [[nodiscard]]
  std::string UnparseSimCommand(const std::vector<std::string>& tokens)
  {
    std::string text;

    for (std::size_t i = 0; i < tokens.size(); ++i) {
      if (i != 0u) {
        text.push_back(' ');
      }

      const std::string& token = tokens[i];
      if (!SimCommandTokenNeedsQuotes(token)) {
        text.append(token);
        continue;
      }

      text.push_back('"');
      for (const char ch : token) {
        if (ch == '\\' || ch == '"') {
          text.push_back('\\');
        }
        text.push_back(ch);
      }
      text.push_back('"');
    }

    return text;
  }

  /**
   * Address: 0x006E1A10 (FUN_006E1A10)
   *
   * What it does:
   * Appends one command id into `CCommandDb::pendingReleasedCmdIds`,
   * growing vector storage when needed.
   */
  void AppendPendingReleasedCommandId(msvc8::vector<CmdId>& pendingReleasedCmdIds, const CmdId cmdId)
  {
    pendingReleasedCmdIds.push_back(cmdId);
  }

  /**
   * Address: 0x006E0EC0 (FUN_006E0EC0, ?RemoveCmd@CCommandDB@Moho@@...)
   *
   * IDA signature:
   * int __stdcall Moho::CCommandDB::RemoveCmd(Moho::CCommandDB *commandDb, Moho::CmdId cmdId);
   *
   * What it does:
   * Removes one command-id entry from the command DB's `commands` map when
   * present (`sub_6E1940`/`sub_6E1670`, `msvc8::map<CmdId,CUnitCommand*>::
   * find`/`erase_node` for this instantiation, cited on `rb_tree::find_node`/
   * `erase_node` in `RbTree.h`), records recycled low-24 ids in the rolling
   * IdPool history slot for source-byte 0x80, and queues the id into the
   * pending-release vector (`FUN_006E1A10`, `AppendPendingReleasedCommandId`).
   *
   * Used to reach into `commandDb` through a bespoke `CCommandDbRuntimeView`
   * cast; `commands`/`pool`/`pendingReleasedCmdIds` are `CCommandDb`'s own
   * real typed members (`CCommandDb.h`), so the cast is gone.
   *
   * The null-`commandDb` guard and the `(cmdId & 0xFF000000) == 0xFF000000`
   * early-out are not present in `FUN_006E0EC0`'s own body -- the mask check
   * is applied at its real call sites instead (e.g. `Moho::UNIT_IssueCommand`,
   * FUN_006F12C0, guards the call with `(cmdId & 0xFF000000) != 0xFF000000`).
   * Kept here defensively: a Sim.cpp call site deliberately passes a possibly
   * null `mCommandDB` relying on this guard, and folding three call-site
   * guards into one is behaviourally equivalent for every real caller.
   */
  void ReleaseCommandIdIfUnconsumed(CCommandDb* commandDb, const CmdId cmdId)
  {
    if (!commandDb) {
      return;
    }

    if ((static_cast<std::uint32_t>(cmdId) & 0xFF000000u) == 0xFF000000u) {
      return;
    }

    const auto it = commandDb->commands.find(cmdId);
    if (it != commandDb->commands.end()) {
      commandDb->commands.erase(it);
    }

    const std::uint32_t commandType = static_cast<std::uint32_t>(cmdId) & 0xFF000000u;
    if (commandType == 0x80000000u) {
      const std::int32_t retireIndex = (commandDb->pool.mSubRes2.mEnd + 99) % 100;
      SimSubRes3& retireSlot = commandDb->pool.mSubRes2.mData[retireIndex];
      AsBitSet(retireSlot).Add(static_cast<std::uint32_t>(cmdId) & 0x00FFFFFFu);
    }

    AppendPendingReleasedCommandId(commandDb->pendingReleasedCmdIds, cmdId);
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00838AE0 (FUN_00838AE0, sub_838AE0)
   *
   * What it does:
   * Bridge for the recovered Sim.cpp-local `CountLiveUserEntityWeakSetEntriesAndPrune`
   * worker: counts live weak-set entries in `set`, pruning tombstone nodes along
   * the way, for callers outside Sim.cpp (`CFormation::ChooseFormation`'s own
   * participant-tracking set). `WeakEntitySetUserEntity` and the Sim.cpp-local
   * `UserEntityWeakSetRuntimeView` share the identical 12-byte
   * `{allocProxy,head,size}` binary layout (both size/offset-asserted), so the
   * reinterpret is a same-shape view, not a layout guess.
   */
  std::int32_t CountLiveUserEntityWeakSetEntriesAndPrune(WeakEntitySetUserEntity& set)
  {
    static_assert(
      sizeof(WeakEntitySetUserEntity) == sizeof(UserEntityWeakSetRuntimeView),
      "WeakEntitySetUserEntity and UserEntityWeakSetRuntimeView must share the same 12-byte layout"
    );
    return CountLiveUserEntityWeakSetEntriesAndPrune(reinterpret_cast<UserEntityWeakSetRuntimeView*>(&set));
  }

  /**
   * Address: 0x008B4AC0 (FUN_008B4AC0, sub_8B4AC0)
   *
   * What it does:
   * Bridge for the recovered Sim.cpp-local `QueueCommandIssueSetTypeEvent`
   * worker (see that function's own doc comment for the full binary
   * evidence): reissues one already-queued command-issue entry's command
   * id/type in place. Exposed (declared in CWldSession.h) so
   * `UserUnit.h`'s `RestartQueuedCommandsFromHelper` - and through it the
   * mouse-drag "restart as Patrol/FormPatrol" keystone
   * (`RestartMoveCommandAsPatrol`, CWldSession.cpp) - can reissue an
   * in-flight order without owning the local ring-queue event mechanics.
   */
  void ReissueCommandIssueEntryAsType(
    UserCommandIssueHelper& helper,
    const CmdId newCmdId,
    const EUnitCommandType newCommandType
  ) noexcept
  {
    QueueCommandIssueSetTypeEvent(
      reinterpret_cast<CommandIssueHelperRuntimeView&>(helper), newCmdId, newCommandType
    );
  }

  /**
   * Address: 0x008B58A0 (FUN_008B58A0, struct_CommandManager::struct_CommandManager)
   *
   * What it does:
   * Stands up an empty manager for one command source. Both sub-objects build
   * themselves: `IdPool` seeds its recycle history and the command map stands
   * up its own head sentinel.
   */
  CommandManager::CommandManager(const std::uint32_t sourceId)
    : mIdPool()
    , mSourceId(static_cast<std::uint8_t>(sourceId))
    , pad_0CB1_0CB4{}
    , mCommands()
  {}

  /**
   * Address: 0x008B5A70 (FUN_008B5A70, struct_CommandManager::FindDataFor /
   * struct_CommandManager::NewCommand)
   *
   * What it does:
   * Finds an existing helper for one command id or constructs and inserts a
   * new command-issue helper, then marks reused helper variable data dirty.
   *
   * Real disassembly calls `std::map_CmdId_CommandIssueHelper::find`
   * (FUN_008B6160) then, on a miss, `sub_8B5DF0` (`insert(const value_type&)`)
   * -- both cited on `rb_tree::find_node`/`insert_unique` in `RbTree.h` for
   * this `msvc8::map<CmdId, UserCommandIssueHelper*>` instantiation
   * (`CommandManager::mCommands`, `CommandManager.h`). This used to reach in
   * through a bespoke `CommandDbMapStorageView`/`CommandDbMapNodeView` pair
   * (`CommandIssueMapOf` + `FindCommandNode`/`InsertCommandNode`) that
   * hand-walked the same real member instead of calling it.
   */
  [[nodiscard]] UserCommandIssueHelper* FindOrCreateCommandIssueHelper(
    CommandManager& commandManager,
    const SSTICommandConstantData& constantData,
    const std::uint8_t deleteWhenDue,
    const std::int32_t dueSeqNo
  )
  {
    const CmdId commandId = static_cast<CmdId>(constantData.cmd);
    const auto it = commandManager.mCommands.find(commandId);
    if (it == commandManager.mCommands.end()) {
      auto* const helper = new UserCommandIssueHelper(constantData, deleteWhenDue, dueSeqNo);
      commandManager.mCommands.insert({commandId, helper});
      return helper;
    }

    UserCommandIssueHelper* const helper = it->second;
    helper->mVariableDataDirty = 1u;
    helper->mDeleteWhenDue = 0u;
    return helper;
  }

  /**
   * Address: 0x008B5C20 (FUN_008B5C20, struct_CommandManager::DeleteCommands)
   *
   * What it does:
   * Deletes command-issue helpers for each supplied command id and recycles
   * ids that belong to the manager's active source byte.
   *
   * Real disassembly calls `std::map_CmdId_CommandIssueHelper::find`
   * (FUN_008B6160, cited on `rb_tree::find_node` in `RbTree.h`) then deletes
   * the mapped helper directly -- it does not erase the node from
   * `mCommands` afterward, leaving a dangling entry behind; that is the
   * binary's own behaviour (every id passed here also gets queued for id-pool
   * recycling below, so a stale map entry never resolves to a live helper
   * again), preserved exactly rather than "fixed" with an added `.erase()`.
   */
  void DeleteCommandIssueHelpers(
    CommandManager& commandManager,
    const msvc8::vector<CmdId>& commandIds
  ) noexcept
  {
    for (const CmdId* cursor = commandIds.begin(); cursor != commandIds.end(); ++cursor) {
      const CmdId commandId = *cursor;
      const auto it = commandManager.mCommands.find(commandId);
      if (it != commandManager.mCommands.end()) {
        delete it->second;
      }

      const std::uint32_t rawCommandId = static_cast<std::uint32_t>(commandId);
      if (static_cast<std::uint8_t>(rawCommandId >> 24u) == commandManager.mSourceId) {
        commandManager.mIdPool.QueueReleasedLowId(rawCommandId & 0x00FFFFFFu);
      }
    }
  }

  /**
   * Address: 0x008B5CF0 (FUN_008B5CF0)
   *
   * What it does:
   * Advances every command-issue helper to the current beat and then ticks
   * the manager id-pool recycle history.
   *
   * Real disassembly walks `mCommands` in ascending-key order via an inlined
   * successor step (the same walk `msvc8::map`'s iterator performs through
   * `rb_increment`), calling `AdvanceLocalEventsToBeat` on each mapped
   * helper; a plain range-for over the map is the same walk.
   */
  void AdvanceCommandIssueHelpersToBeat(
    CommandManager& commandManager,
    const std::int32_t beat
  ) noexcept
  {
    for (auto& [commandId, helper] : commandManager.mCommands) {
      helper->AdvanceLocalEventsToBeat(beat);
    }

    commandManager.mIdPool.Update();
  }
} // namespace moho

namespace
{
  [[nodiscard]] CUnitCommand* AddIssueDataToCommandDb(
    CCommandDb* const commandDb,
    const SSTICommandIssueData& issueData
  )
  {
    return commandDb ? commandDb->AddIssueData(issueData) : nullptr;
  }

  [[nodiscard]] bool IsUnitIdleState(Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return true;
    }

    return unit->CommandQueue->GetCurrentCommand() == nullptr;
  }

  [[nodiscard]] Unit* GetTransportedBy(const Unit* const unit) noexcept
  {
    return (unit != nullptr) ? unit->TransportedByRef.ResolveObjectPtr<Unit>() : nullptr;
  }

  [[nodiscard]] Unit* GetTransportFerryBeacon(Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return nullptr;
    }

    CUnitCommand* const currentCommand = unit->CommandQueue->GetCurrentCommand();
    if (currentCommand == nullptr) {
      return nullptr;
    }

    return currentCommand->mUnit.GetObjectPtr();
  }

  [[nodiscard]] bool HasCommandCap(const Unit* const unit, const ERuleBPUnitCommandCaps commandCap) noexcept
  {
    return unit != nullptr && (unit->GetAttributes().commandCapsMask & static_cast<std::uint32_t>(commandCap)) != 0u;
  }

  [[nodiscard]] bool IsValidTargetPosition(const Wm3::Vec3f& targetPosition) noexcept
  {
    return Wm3::Vector3fIsntNaN(&targetPosition);
  }

  [[nodiscard]] bool IsDuplicateSuppressionCommand(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Reclaim:
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Capture:
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Upgrade:
      case EUnitCommandType::UNITCOMMAND_Sacrifice:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
      case EUnitCommandType::UNITCOMMAND_Dock:
        return true;
      default:
        break;
    }

    return false;
  }

  [[nodiscard]] bool CommandUnitSetMatchesSelection(
    const SCommandUnitSet& commandUnits,
    const SEntitySetTemplateUnit& selectedUnits
  ) noexcept
  {
    std::size_t commandUnitCount = 0;
    for (CScriptObject* const* it = commandUnits.mVec.begin(); it != commandUnits.mVec.end(); ++it) {
      const CScriptObject* const entry = *it;
      if (!SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      if (SCommandUnitSet::UnitFromEntry(entry) != nullptr) {
        ++commandUnitCount;
      }
    }

    if (commandUnitCount != selectedUnits.mVec.size()) {
      return false;
    }

    for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
      const Unit* const selectedUnit = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (selectedUnit == nullptr) {
        return false;
      }

      bool found = false;
      for (CScriptObject* const* jt = commandUnits.mVec.begin(); jt != commandUnits.mVec.end(); ++jt) {
        const CScriptObject* const entry = *jt;
        if (!SCommandUnitSet::IsUsableEntry(entry)) {
          continue;
        }

        const Unit* const commandUnit = SCommandUnitSet::UnitFromEntry(entry);
        if (commandUnit == selectedUnit) {
          found = true;
          break;
        }
      }

      if (!found) {
        return false;
      }
    }

    return true;
  }

  [[nodiscard]] Unit* ResolveTargetUnit(Entity* const entity) noexcept
  {
    return entity != nullptr ? entity->IsUnit() : nullptr;
  }

  [[nodiscard]] Unit* ResolveTargetUnitOrReconCreator(Entity* const entity) noexcept
  {
    if (entity == nullptr) {
      return nullptr;
    }

    if (ReconBlip* const blip = entity->IsReconBlip(); blip != nullptr) {
      return blip->GetCreator();
    }

    return entity->IsUnit();
  }

  [[nodiscard]] bool CategoryCachesIntersect(
    const RUnitBlueprint* const lhsBlueprint,
    const RUnitBlueprint* const rhsBlueprint
  )
  {
    if (lhsBlueprint == nullptr || rhsBlueprint == nullptr) {
      return false;
    }

    const auto& lhsCategories = reinterpret_cast<const CategoryWordRangeView&>(lhsBlueprint->Economy.CategoryCache);
    const auto& rhsCategories = reinterpret_cast<const CategoryWordRangeView&>(rhsBlueprint->Economy.CategoryCache);
    const BVIntSet& lhsBits = CategoryWordRangeAsBVIntSet(lhsCategories);
    const BVIntSet& rhsBits = CategoryWordRangeAsBVIntSet(rhsCategories);

    BVIntSet intersection{};
    lhsBits.Intersect(&intersection, &rhsBits);
    return intersection.Count() != 0u;
  }

  [[nodiscard]] bool HasBlueprintInCategory(
    const Sim* const sim,
    const REntityBlueprint* const blueprint,
    const char* const categoryName
  )
  {
    if (sim == nullptr || sim->mRules == nullptr || blueprint == nullptr || categoryName == nullptr) {
      return false;
    }

    const CategoryWordRangeView* const categoryRange = sim->mRules->GetEntityCategory(categoryName);
    const EntityCategorySet* const categorySet =
      categoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(categoryRange) : nullptr;
    return categorySet != nullptr && EntityCategory::HasBlueprint(blueprint, categorySet);
  }

  [[nodiscard]] bool EqualsNoCase(const char* const lhs, const char* const rhs) noexcept
  {
    const char* const safeLhs = lhs != nullptr ? lhs : "";
    const char* const safeRhs = rhs != nullptr ? rhs : "";
    return _stricmp(safeLhs, safeRhs) == 0;
  }

  /**
   * Address: 0x006EF660 (FUN_006EF660, sub_6EF660)
   *
   * What it does:
   * For `TransportReverseLoadUnits`, replaces the incoming selected-unit set
   * with one best transport candidate plus the requested target unit.
   */
  void RetargetReverseLoadUnits(
    const SSTICommandIssueData& issueData,
    Sim* const sim,
    SEntitySetTemplateUnit& selectedUnits
  )
  {
    if (sim == nullptr || issueData.mCommandType != EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits) {
      return;
    }

    SEntitySetTemplateUnit originalSelection{};
    for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
      originalSelection.mVec.PushBack(*it);
    }
    selectedUnits.Clear();

    Entity* const targetEntity = FindEntityById(sim->mEntityDB, static_cast<EntId>(issueData.mTarget.mEntityId));
    Unit* const targetUnit = targetEntity != nullptr ? targetEntity->IsUnit() : nullptr;
    if (targetUnit == nullptr || targetUnit->IsDead() || !targetUnit->IsMobile()) {
      return;
    }

    const RUnitBlueprint* const targetBlueprint = targetUnit->GetBlueprint();
    Unit* bestTransport = nullptr;
    float bestScore = std::numeric_limits<float>::infinity();

    for (Entity* const* it = originalSelection.mVec.begin(); it != originalSelection.mVec.end(); ++it) {
      Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (candidate == nullptr || candidate->IsDead() || candidate->IsBeingBuilt()) {
        continue;
      }

      if (!candidate->IsInCategory("TRANSPORTATION") && !candidate->IsInCategory("AIRSTAGINGPLATFORM")
          && !candidate->IsInCategory("TELEPORTATION")) {
        continue;
      }

      IAiTransport* const transport = candidate->AiTransport;
      if (transport == nullptr || !transport->TransportHasSpaceFor(targetBlueprint)) {
        continue;
      }

      const Wm3::Vec3f& targetPos = targetUnit->GetPosition();
      const Wm3::Vec3f& candidatePos = candidate->GetPosition();
      const float dx = candidatePos.x - targetPos.x;
      const float dz = candidatePos.z - targetPos.z;
      float score = std::sqrt((dx * dx) + (dz * dz));
      if (IsUnitIdleState(candidate)) {
        score *= 0.5f;
      }

      if (score < bestScore) {
        bestScore = score;
        bestTransport = candidate;
      }
    }

    if (bestTransport != nullptr) {
      (void)selectedUnits.AddUnit(bestTransport);
      (void)selectedUnits.AddUnit(targetUnit);
    }
  }

  [[nodiscard]] bool IsOutsideArmyNoRushRadius(const CArmyImpl* const army, const CAiTarget& target) noexcept
  {
    if (army == nullptr || army->NoRushTicks <= 0 || target.targetType == EAiTargetType::AITARGET_None) {
      return false;
    }

    const float dx = (army->StartPosition.x + army->NoRushOffsetX) - target.position.x;
    const float dz = (army->StartPosition.y + army->NoRushOffsetY) - target.position.z;
    return std::sqrt((dx * dx) + (dz * dz)) > army->NoRushRadius;
  }

  /**
   * Address: 0x006EF9E0 (FUN_006EF9E0, func_ProcessUnitCommand)
   *
   * What it does:
   * Applies per-unit command-family validation and rejection side-effects
   * before queue insertion in `UNIT_IssueCommand`.
   */
  [[nodiscard]] bool ProcessIssuedUnitCommand(
    Sim* const sim,
    const SSTICommandIssueData& commandIssueData,
    Unit* const unit,
    const bool clearQueue,
    const SEntitySetTemplateUnit& selectedUnits
  )
  {
    if (sim == nullptr || unit == nullptr) {
      return false;
    }

    Entity* const targetEntity = FindEntityById(sim->mEntityDB, static_cast<EntId>(commandIssueData.mTarget.mEntityId));
    CUnitCommandQueue* const queue = unit->CommandQueue;

    if (unit->IsDead()) {
      return false;
    }

    if (unit->IsBeingBuilt() && !unit->IsInCategory("FACTORY")) {
      return false;
    }

    if (queue != nullptr && IsDuplicateSuppressionCommand(commandIssueData.mCommandType)) {
      CUnitCommand* const currentCommand = queue->GetCurrentCommand();
      if (clearQueue && currentCommand != nullptr && currentCommand->mVarDat.mCmdType == commandIssueData.mCommandType
          && queue->GetNextCommand() == nullptr) {
        bool sameTarget = false;
        switch (commandIssueData.mTarget.mType) {
          case EAiTargetType::AITARGET_Entity:
            sameTarget = commandIssueData.mTarget.mEntityId == currentCommand->mVarDat.mTarget1.mEntityId;
            break;
          case EAiTargetType::AITARGET_Ground: {
            const Wm3::Vec3f& currentTargetPos = currentCommand->mVarDat.mTarget1.mPos;
            const float dx = commandIssueData.mTarget.mPos.x - currentTargetPos.x;
            const float dy = commandIssueData.mTarget.mPos.y - currentTargetPos.y;
            const float dz = commandIssueData.mTarget.mPos.z - currentTargetPos.z;
            sameTarget = std::sqrt((dx * dx) + (dy * dy) + (dz * dz)) < 0.001f;
            break;
          }
          default:
            break;
        }

        if (sameTarget && CommandUnitSetMatchesSelection(currentCommand->mUnitSet, selectedUnits)) {
          return false;
        }
      }
    }

    if (commandIssueData.mTarget.mType != EAiTargetType::AITARGET_None) {
      const Wm3::Vec3f targetPosition = targetEntity != nullptr ? targetEntity->Position : commandIssueData.mTarget.mPos;
      CArmyImpl* const army = unit->ArmyRef;

      if (sim->mMapData != nullptr && army != nullptr && !sim->mMapData->IsWithin(targetPosition, 0.0f, army->UseWholeMap())) {
        return false;
      }

      CAiTarget noRushTarget{};
      noRushTarget.targetType = commandIssueData.mTarget.mType;
      noRushTarget.position = targetPosition;
      if (IsOutsideArmyNoRushRadius(army, noRushTarget)) {
        return false;
      }
    }

    if (unit->IsUnitState(UNITSTATE_Enhancing) && clearQueue
        && commandIssueData.mCommandType != EUnitCommandType::UNITCOMMAND_Stop) {
      return false;
    }

    switch (commandIssueData.mCommandType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove: {
        Unit* const transportedBy = GetTransportedBy(unit);
        const bool invalidTransportState =
          transportedBy != nullptr && (unit->IsInCategory("POD") || transportedBy->IsInCategory("CARRIER"));
        if (invalidTransportState || !unit->IsMobile() || !IsValidTargetPosition(commandIssueData.mTarget.mPos)
            || commandIssueData.mTarget.mType == EAiTargetType::AITARGET_None) {
          return false;
        }
        return true;
      }
      case EUnitCommandType::UNITCOMMAND_Dive: {
        const RUnitBlueprint* const blueprint = unit->GetBlueprint();
        return blueprint != nullptr && blueprint->Physics.MotionType == RULEUMT_SurfacingSub;
      }
      case EUnitCommandType::UNITCOMMAND_BuildFactory:
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
        return unit->IsInCategory("FACTORY") || unit->IsInCategory("ENGINEER") || unit->IsInCategory("NEEDMOBILEBUILD")
          || unit->IsInCategory("POD");
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
        if (!unit->IsMobile() && unit->AiAttacker == nullptr) {
          return false;
        }
        if (targetEntity != nullptr && targetEntity->ArmyRef != nullptr && unit->ArmyRef != nullptr
            && targetEntity->ArmyRef->GetAllianceWith(unit->ArmyRef) == ALLIANCE_Ally) {
          return false;
        }
        return true;
      case EUnitCommandType::UNITCOMMAND_Teleport:
        return HasCommandCap(unit, RULEUCC_Teleport);
      case EUnitCommandType::UNITCOMMAND_Guard: {
        Unit* const transportedBy = GetTransportedBy(unit);
        if ((transportedBy != nullptr && (transportedBy->IsInCategory("CARRIER") || unit->IsInCategory("POD")))
            || !HasCommandCap(unit, RULEUCC_Guard)) {
          return false;
        }

        Unit* const targetUnit = ResolveTargetUnit(targetEntity);
        if (targetUnit == nullptr) {
          return unit->IsMobile();
        }

        if (unit == targetUnit) {
          return false;
        }

        if (!targetUnit->IsMobile() && !unit->IsMobile() && targetUnit->IsInCategory("FACTORY") && unit->IsInCategory("FACTORY")
            && !CategoryCachesIntersect(unit->GetBlueprint(), targetUnit->GetBlueprint())) {
          return false;
        }

        if (targetUnit->IsInCategory("FERRYBEACON") && GetTransportFerryBeacon(unit) == targetUnit) {
          return false;
        }

        const bool unitIsFactory = HasBlueprintInCategory(sim, unit->GetBlueprint(), "FACTORY");
        const bool targetIsFactory = HasBlueprintInCategory(sim, targetUnit->GetBlueprint(), "FACTORY");
        if (unitIsFactory && !targetIsFactory) {
          return false;
        }

        return targetUnit->GetGuardedUnit() != unit;
      }
      case EUnitCommandType::UNITCOMMAND_Ferry:
        return GetTransportedBy(unit) == nullptr && unit->IsInCategory("TRANSPORTATION") && unit->AiTransport != nullptr;
      case EUnitCommandType::UNITCOMMAND_Reclaim: {
        if ((GetTransportedBy(unit) != nullptr && unit->IsInCategory("POD")) || !unit->IsInCategory("RECLAIM")) {
          return false;
        }

        if (targetEntity != nullptr && !targetEntity->IsBeingBuilt()) {
          if (targetEntity->BluePrint == nullptr || !targetEntity->IsInCategory("RECLAIMABLE")
              || targetEntity->mCurrentLayer == LAYER_Air) {
            return false;
          }

          Unit* const sourceUnit = ResolveTargetUnitOrReconCreator(targetEntity);
          if (sourceUnit != nullptr && !sourceUnit->GetAttributes().mReclaimable) {
            return false;
          }
        }

        return true;
      }
      case EUnitCommandType::UNITCOMMAND_Capture: {
        if ((GetTransportedBy(unit) != nullptr && unit->IsInCategory("POD")) || !unit->IsInCategory("CAPTURE")) {
          return false;
        }

        if (targetEntity != nullptr) {
          Unit* const targetUnit = ResolveTargetUnitOrReconCreator(targetEntity);
          if (targetUnit == nullptr || !targetUnit->GetAttributes().mCapturable) {
            return false;
          }

          if ((unit->ArmyRef != nullptr && targetUnit->ArmyRef != nullptr
               && unit->ArmyRef->GetAllianceWith(targetUnit->ArmyRef) == ALLIANCE_Ally)
              || targetUnit->IsDead() || targetUnit->IsBeingBuilt()) {
            return false;
          }
        }

        return true;
      }
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Sacrifice: {
        if (commandIssueData.mCommandType == EUnitCommandType::UNITCOMMAND_Sacrifice
            && !HasCommandCap(unit, RULEUCC_Sacrifice)) {
          return false;
        }

        if (targetEntity == nullptr) {
          return false;
        }

        if ((GetTransportedBy(unit) != nullptr && unit->IsInCategory("POD")) || !unit->IsInCategory("REPAIR")) {
          return false;
        }

        if (unit->ArmyRef != nullptr && targetEntity->ArmyRef != nullptr
            && unit->ArmyRef->GetAllianceWith(targetEntity->ArmyRef) == ALLIANCE_Enemy) {
          return false;
        }

        if (Unit* const targetUnit = ResolveTargetUnit(targetEntity); targetUnit != nullptr && targetUnit == unit) {
          return false;
        }

        return HasBlueprintInCategory(sim, unit->GetBlueprint(), "REPAIR");
      }
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Dock: {
        if (GetTransportedBy(unit) != nullptr || unit->IsInCategory("PODS")) {
          return false;
        }

        Unit* const targetUnit = ResolveTargetUnit(targetEntity);
        if (targetUnit == nullptr) {
          return true;
        }

        if ((targetUnit != unit && !HasCommandCap(unit, RULEUCC_CallTransport)) || targetUnit->mCurrentLayer == LAYER_Seabed) {
          return false;
        }

        const bool usesSpecialFerryFactoryLane =
          targetUnit->IsInCategory("FERRYBEACON")
          || (targetUnit->IsInCategory("FACTORY") && !targetUnit->IsInCategory("AIRSTAGINGPLATFORM")
              && !targetUnit->IsInCategory("TELEPORTATION"));
        if (!usesSpecialFerryFactoryLane) {
          IAiTransport* const targetTransport = targetUnit->AiTransport;
          if (targetUnit->IsDead() || targetUnit->IsBeingBuilt() || targetTransport == nullptr) {
            return false;
          }

          if (targetUnit == unit || targetTransport->TransportCanCarryUnit(unit)) {
            return true;
          }

          (void)targetUnit->RunScript("OnTransportReject");
          return false;
        }

        if (targetUnit->IsInCategory("FERRYBEACON") && GetTransportFerryBeacon(unit) == targetUnit) {
          return false;
        }

        if (unit->IsMobile() && !HasBlueprintInCategory(sim, unit->GetBlueprint(), "TRANSPORTATION")) {
          return true;
        }

        return false;
      }
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits: {
        if ((!unit->IsMobile() && !unit->IsInCategory("AIRSTAGINGPLATFORM")) || GetTransportedBy(unit) != nullptr
            || unit->IsInCategory("PODS")) {
          return false;
        }

        if (selectedUnits.Empty()) {
          return false;
        }

        Unit* candidateTransport = nullptr;
        for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
          Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(*it);
          if (candidate == nullptr || candidate->IsDead() || candidate->IsBeingBuilt() || candidate->AiTransport == nullptr) {
            continue;
          }

          candidateTransport = candidate;
          Unit* const targetUnit = ResolveTargetUnit(targetEntity);
          if (targetUnit == nullptr) {
            if (candidateTransport != unit) {
              (void)candidateTransport->RunScript("OnTransportReject");
            }
            return false;
          }

          if (!candidate->AiTransport->TransportCanCarryUnit(targetUnit)) {
            continue;
          }

          if (candidate->mCurrentLayer == LAYER_Seabed) {
            return false;
          }

          return true;
        }

        if (candidateTransport != nullptr && candidateTransport != unit) {
          (void)candidateTransport->RunScript("OnTransportReject");
        }
        return false;
      }
      case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
        return unit->mCurrentLayer != LAYER_Seabed && (unit->AiTransport != nullptr || GetTransportedBy(unit) != nullptr);
      case EUnitCommandType::UNITCOMMAND_Upgrade: {
        const RUnitBlueprint* const upgradeBlueprint = commandIssueData.mBlueprint;
        const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
        if (upgradeBlueprint == nullptr || unitBlueprint == nullptr) {
          return false;
        }

        // FAF Binary Patch (non-1:1 with original binary):
        // The retail path allows restricted upgrades to pass initial validation,
        // which can later reach CUnitUpgradeTask::TaskTick (FUN_005F8890) and
        // crash on a null-vtable weak-focus dereference at 0x005F8B20.
        // Fixed behavior: reject restricted upgrades at issue time (including
        // restricted mex tier-up), so the crashing task path is never entered.
        // Related: https://github.com/FAForever/FA-Binary-Patches/issues/125
        if (!unit->CanBuild(upgradeBlueprint)) {
          return false;
        }

        const char* const seedUnitId = upgradeBlueprint->General.SeedUnit.name.c_str();
        if (seedUnitId != nullptr && seedUnitId[0] != '\0') {
          if (!EqualsNoCase(unitBlueprint->mBlueprintId.c_str(), seedUnitId)
              && !EqualsNoCase(unitBlueprint->General.UpgradesFromBase.name.c_str(), seedUnitId)) {
            return false;
          }
        } else {
          const char* const unitUpgradesTo = unitBlueprint->General.UpgradesTo.name.c_str();
          if (unitUpgradesTo == nullptr || unitUpgradesTo[0] == '\0') {
            return false;
          }

          const char* const requiredSourceId = upgradeBlueprint->General.UpgradesFromBase.name.c_str();
          if (!EqualsNoCase(requiredSourceId, "none")) {
            if (!EqualsNoCase(unitBlueprint->mBlueprintId.c_str(), requiredSourceId)
                && !EqualsNoCase(unitBlueprint->General.UpgradesFromBase.name.c_str(), requiredSourceId)) {
              return false;
            }
          } else if (!EqualsNoCase(unitUpgradesTo, upgradeBlueprint->mBlueprintId.c_str())
                     && !EqualsNoCase(unitUpgradesTo, upgradeBlueprint->General.UpgradesFrom.name.c_str())) {
            return false;
          }
        }

        unit->DirtySyncState = 1;
        CUnitCommand* const lastCommand = queue != nullptr ? queue->GetLastCommand() : nullptr;
        if (lastCommand != nullptr && lastCommand->mVarDat.mCmdType == commandIssueData.mCommandType) {
          const REntityBlueprint* const lastBlueprint = lastCommand->mConstDat.blueprint;
          if (lastBlueprint != nullptr && EqualsNoCase(lastBlueprint->mBlueprintId.c_str(), upgradeBlueprint->mBlueprintId.c_str())) {
            return false;
          }
        }

        return true;
      }
      case EUnitCommandType::UNITCOMMAND_KillSelf:
        return !unit->IsBeingBuilt() && unit->RunScriptUnitBool("CheckCanBeKilled", unit);
      case EUnitCommandType::UNITCOMMAND_OverCharge:
        return HasCommandCap(unit, RULEUCC_Overcharge);
      case EUnitCommandType::UNITCOMMAND_SpecialAction:
        return HasCommandCap(unit, RULEUCC_SpecialAction);
      default:
        return true;
    }
  }

  /**
   * Address: 0x006F14D0 (FUN_006F14D0, Moho::UNIT_IssueFactoryCommand)
   *
   * What it does:
   * Iterates selected factories, rejects invalid/no-rush/transported lanes,
   * lazily allocates one shared command, then enqueues it into each eligible
   * factory builder queue (optionally clearing queue first).
   */
  [[nodiscard]] CUnitCommand* IssueFactoryCommandToSelectedUnitsImpl(
    Sim* const sim,
    const SEntitySetTemplateUnit& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    if (!sim) {
      return nullptr;
    }

    CAiTarget target{};
    target.DecodeFromSSTITarget(commandIssueData.mTarget, sim);

    CUnitCommand* issuedCommand = nullptr;
    for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (!unit || unit->IsDead()) {
        continue;
      }

      if (unit->TransportedByRef.ResolveObjectPtr<Unit>() != nullptr) {
        continue;
      }

      if (IsOutsideArmyNoRushRadius(unit->ArmyRef, target)) {
        continue;
      }

      auto* const builder = static_cast<CAiBuilderImpl*>(unit->AiBuilder);
      if (!builder || !builder->BuilderIsFactory()) {
        continue;
      }

      if (!issuedCommand) {
        issuedCommand = AddIssueDataToCommandDb(sim->mCommandDB, commandIssueData);
        if (!issuedCommand) {
          break;
        }
        issuedCommand->mUnknownFlag142 = true;
      }

      if (clearQueue) {
        builder->BuilderClearFactoryCommandQueue();
      }

      builder->BuilderAddFactoryCommand(issuedCommand, -1);
    }

    if (!issuedCommand) {
      ReleaseCommandIdIfUnconsumed(sim->mCommandDB, commandIssueData.nextCommandId);
    }

    return issuedCommand;
  }

  /**
   * Address: 0x006F12C0 (FUN_006F12C0, UNIT_IssueCommand)
   *
   * What it does:
   * Validates each selected unit through `func_ProcessUnitCommand`, creates one
   * shared command object lazily, and appends/inserts it into eligible queues.
   */
  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnitsImpl(
    Sim* const sim,
    SEntitySetTemplateUnit& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    if (sim == nullptr || sim->mCommandDB == nullptr) {
      ReleaseCommandIdIfUnconsumed(sim ? sim->mCommandDB : nullptr, commandIssueData.nextCommandId);
      return nullptr;
    }

    RetargetReverseLoadUnits(commandIssueData, sim, selectedUnits);

    CUnitCommand* issuedCommand = nullptr;
    bool queuedAtLeastOnce = false;
    const std::uint32_t commandIdTopByte = static_cast<std::uint32_t>(commandIssueData.nextCommandId) & 0xFF000000u;
    const bool appendByDefault = commandIdTopByte == 0xFF000000u;

    for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
      CUnitCommandQueue* const queue = (unit != nullptr) ? unit->CommandQueue : nullptr;
      if (queue == nullptr) {
        continue;
      }

      if (!ProcessIssuedUnitCommand(sim, commandIssueData, unit, clearQueue, selectedUnits)) {
        continue;
      }

      const std::size_t queueSize = queue->mCommandVec.size();
      if (queueSize > 500u && !clearQueue) {
        continue;
      }

      if (issuedCommand == nullptr) {
        issuedCommand = AddIssueDataToCommandDb(sim->mCommandDB, commandIssueData);
        if (issuedCommand == nullptr) {
          break;
        }
      }

      if (clearQueue) {
        queue->mCommandType = commandIssueData.mCommandType;
        queue->ClearCommandQueue();
      }

      if (appendByDefault) {
        queue->AddCommandToQueue(issuedCommand);
        queuedAtLeastOnce = true;
        continue;
      }

      const int insertIndex = queue->FindCommandIndex(commandIssueData.nextCommandId);
      if (insertIndex >= 0) {
        queue->InsertCommandToQueue(issuedCommand, insertIndex);
        queuedAtLeastOnce = true;
      }
    }

    if (issuedCommand == nullptr || !queuedAtLeastOnce) {
      ReleaseCommandIdIfUnconsumed(sim->mCommandDB, commandIssueData.nextCommandId);
    }

    return queuedAtLeastOnce ? issuedCommand : nullptr;
  }

  // 0x00748AA0 resolves unit blueprints from RResId via RRuleGameRules::GetUnitBlueprint.
  const RUnitBlueprint* ResolveUnitBlueprint(RRuleGameRules* rules, const RResId& blueprintId)
  {
    if (!rules) {
      return nullptr;
    }

    return rules->GetUnitBlueprint(blueprintId);
  }

  /**
   * Address: 0x006EF150 (FUN_006EF150, func_GetUnitBlueprint)
   *
   * What it does:
   * Resolves one Lua blueprint-id argument into `RUnitBlueprint*`, raising a
   * typed Lua error for non-string non-nil values.
   */
  [[nodiscard]] RUnitBlueprint* ResolveUnitBlueprintFromLuaArgumentImpl(
    LuaPlus::LuaState* const state,
    const LuaPlus::LuaStackObject& blueprintObject,
    const char* const functionName
  )
  {
    if (!state || !state->m_state || !blueprintObject.m_state || !blueprintObject.m_state->m_state) {
      return nullptr;
    }

    lua_State* const rawState = blueprintObject.m_state->m_state;
    if (lua_isstring(rawState, blueprintObject.m_stackIndex)) {
      const char* const blueprintIdText = lua_tostring(rawState, blueprintObject.m_stackIndex);
      if (blueprintIdText == nullptr) {
        blueprintObject.TypeError("string");
      }

      RResId lookupId{};
      gpg::STR_InitFilename(&lookupId.name, blueprintIdText);

      Sim* const sim = ResolveGlobalSim(state->m_state);
      if (sim == nullptr || sim->mRules == nullptr) {
        return nullptr;
      }

      return sim->mRules->GetUnitBlueprint(lookupId);
    }

    if (lua_type(rawState, blueprintObject.m_stackIndex) != 0) {
      const LuaPlus::LuaObject blueprintValue(blueprintObject);
      const char* const typeName = blueprintValue.TypeName();
      LuaPlus::LuaState::Error(
        state,
        "Invalid blueprint in %s; expected a string but got a %s",
        functionName != nullptr ? functionName : "",
        typeName != nullptr ? typeName : ""
      );
    }

    return nullptr;
  }

  // Ground truth (`FUN_00748AA0`, `Sim::CreateUnit`'s inlined call to this
  // helper; confirmed from the .asm's literal `call Moho__EulerRollToQuat`)
  // builds the spawn orientation via `Moho::EulerRollToQuat`, which writes
  // this engine's `.x`-scalar convention directly -- not
  // `Wm3::Quatf::MakeFromAxisAngle` (a FAF-added WildMagic-style helper that
  // writes cos(half) into the native `.w` lane), which produced a
  // `.w`-scalar-tagged-as-`.x` quaternion for every spawned unit's initial
  // heading. Same pattern as `Unit::PredictAheadBomb`'s earlier fix.
  VTransform BuildUnitSpawnTransform(const SCoordsVec2& pos, const float heading)
  {
    const Wm3::Vec3f headingAxis{0.0f, 1.0f, 0.0f};
    Wm3::Quatf orientation{};
    (void)EulerRollToQuat(&headingAxis, &orientation, heading);
    const Wm3::Vec3f worldPosition{pos.x, 0.0f, pos.z};
    return VTransform(worldPosition, orientation);
  }



  /**
   * Address: 0x00748C00 (FUN_00748C00)
   *
   * What it does:
   * Builds an identity transform at world position and executes PROP_Create chain.
   */
  void SpawnPropByBlueprint(Sim* sim, RRuleGameRules* rules, const char* blueprintId, const Wm3::Vec3f& worldPos)
  {
    if (!sim || !blueprintId || !*blueprintId) {
      return;
    }

    PropCreateTransformWords words{};
    // VTransform quaternion lanes are stored as (w,x,y,z) in the first four floats.
    words.orientX = 1.0f; // identity scalar lane
    words.posX = worldPos.x;
    words.posY = worldPos.y;
    words.posZ = worldPos.z;

    VTransform spawnXform{};
    static_assert(
      sizeof(VTransform) == sizeof(PropCreateTransformWords), "VTransform size must be 0x1C for prop spawn path"
    );
    std::memcpy(&spawnXform, &words, sizeof(spawnXform));

    (void)PROP_Create(sim, spawnXform, blueprintId);
  }

  // 0x00748D50 queues silo builds through CAiSiloBuildImpl (0=tactical, 1=nuke).
  bool QueueSiloBuildRequest(Unit* unit, const int modeIndex)
  {
    if (!unit || !unit->AiSiloBuild) {
      return false;
    }

    return unit->AiSiloBuild->SiloAddBuild(static_cast<ESiloType>(modeIndex));
  }

  // 0x00748CD0 applies orientation+position in one call via Entity::Warp.
  void ApplyWarpTransform(Entity* entity, const VTransform& transform)
  {
    if (!entity) {
      return;
    }

    entity->Warp(transform);
  }

  struct RUnitBlueprintIdView
  {
    msvc8::string id;
  };

  static_assert(
    sizeof(RUnitBlueprintIdView) == sizeof(msvc8::string), "RUnitBlueprintIdView layout must match msvc8::string"
  );

  const char* ResolveBlueprintIdCString(const Entity* entity)
  {
    if (!entity || !entity->BluePrint) {
      return "";
    }

    const auto* blueprint = reinterpret_cast<const RUnitBlueprintIdView*>(entity->BluePrint);
    return blueprint->id.raw_data_unsafe();
  }

  /**
   * Address: 0x00528180 (FUN_00528180)
   *
   * What it does:
   * Updates one MD5 context with a nullable C-string lane, hashing either the
   * source text including terminator or the literal `"<NULL>"` fallback.
   */
  void UpdateChecksumWithNullableCString(gpg::MD5Context& context, const char* const text)
  {
    if (text != nullptr) {
      context.Update(text, std::strlen(text) + 1u);
    } else {
      context.Update("<NULL>", 6u);
    }
  }

  std::uint32_t FloatBits(const float value)
  {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
  }

  void ReadEntityVelocity(Entity* entity, Wm3::Vec3f* outVelocity)
  {
    if (!entity || !outVelocity) {
      return;
    }

    *outVelocity = entity->GetVelocity();
  }

  /**
   * Address: 0x00754C60 (FUN_00754C60, sub_754C60)
   *
   * What it does:
   * Core Sim load-serialization routine used by Sim serializer callback.
   */
  gpg::RType* FindRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::TypeMap& map = gpg::GetRTypeMap();
    for (const char* name : names) {
      if (!name || !*name) {
        continue;
      }
      auto it = map.find(name);
      if (it != map.end()) {
        return it->second;
      }
      for (auto jt = map.begin(); jt != map.end(); ++jt) {
        const char* registered = jt->first;
        if (registered && std::strstr(registered, name) != nullptr) {
          return jt->second;
        }
      }
    }
    return nullptr;
  }

  gpg::RType* RequireRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::RType* type = FindRTypeByNameAny(names);
    GPG_ASSERT(type != nullptr);
    return type;
  }

  gpg::RType* CachedSimType()
  {
    if (!Sim::sType) {
      Sim::sType = gpg::LookupRType(typeid(Sim));
    }
    return Sim::sType;
  }

  gpg::RType* LookupRTypeWithTinyThreadCache(const std::type_info& dynamicTypeInfo)
  {
    struct CachedTypeInfoEntry
    {
      const std::type_info* typeInfo;
      gpg::RType* type;
    };

    thread_local std::array<CachedTypeInfoEntry, 3> cache{};

    for (std::size_t i = 0; i < cache.size(); ++i) {
      const CachedTypeInfoEntry& entry = cache[i];
      if (entry.typeInfo == nullptr || entry.type == nullptr) {
        continue;
      }

      if (entry.typeInfo == &dynamicTypeInfo || *entry.typeInfo == dynamicTypeInfo) {
        if (i != 0u) {
          const CachedTypeInfoEntry hit = entry;
          for (std::size_t j = i; j > 0u; --j) {
            cache[j] = cache[j - 1u];
          }
          cache[0] = hit;
        }
        return cache[0].type;
      }
    }

    gpg::RType* const resolved = gpg::LookupRType(dynamicTypeInfo);
    for (std::size_t i = cache.size() - 1u; i > 0u; --i) {
      cache[i] = cache[i - 1u];
    }
    cache[0] = CachedTypeInfoEntry{&dynamicTypeInfo, resolved};
    return resolved;
  }

  /**
   * Address: 0x00585690 (FUN_00585690, func_RRefSim)
   *
   * IDA signature:
   * gpg::RRef *__cdecl func_RRefSim(gpg::RRef *outRef, Moho::Sim *sim);
   *
   * What it does:
   * Builds owner `RRef` for Sim serializer paths. Exact `Sim` pointers keep
   * static type; derived runtime types are resolved and back-adjusted to the
   * complete object start.
   */
  gpg::RRef MakeSimOwnerRef(Sim* sim)
  {
    gpg::RType* const simType = CachedSimType();

    gpg::RRef out{};
    out.mObj = sim;
    out.mType = simType;
    if (!sim) {
      return out;
    }

    const std::type_info& dynamicTypeInfo = typeid(*sim);
    if (dynamicTypeInfo == typeid(Sim)) {
      return out;
    }

    gpg::RType* const dynamicType = LookupRTypeWithTinyThreadCache(dynamicTypeInfo);

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType && simType && dynamicType->IsDerivedFrom(simType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mType = dynamicType ? dynamicType : simType;
      return out;
    }

    out.mObj = static_cast<void*>(reinterpret_cast<char*>(sim) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  void SaveObjectByRType(
    gpg::WriteArchive* archive,
    void* object,
    const std::initializer_list<const char*>& typeNames,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serSaveFunc_ != nullptr);
    type->serSaveFunc_(archive, reinterpret_cast<int>(object), type->version_, const_cast<gpg::RRef*>(&ownerRef));
  }

  void LoadObjectByRType(
    gpg::ReadArchive* archive,
    void* object,
    const std::initializer_list<const char*>& typeNames,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serLoadFunc_ != nullptr);
    type->serLoadFunc_(archive, reinterpret_cast<int>(object), type->version_, const_cast<gpg::RRef*>(&ownerRef));
  }

  void WriteArchiveUIntCompat(gpg::WriteArchive* archive, const std::uint32_t value)
  {
    if (!archive) {
      return;
    }

    if constexpr (requires(gpg::WriteArchive* a) { a->WriteUInt(0u); }) {
      archive->WriteUInt(static_cast<unsigned int>(value));
    } else {
      archive->WriteULong(static_cast<unsigned long>(value));
    }
  }

  void SavePointerByRType(
    gpg::WriteArchive* archive,
    void* object,
    const std::initializer_list<const char*>& typeNames,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = RequireRTypeByNameAny(typeNames);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  void* LoadPointerByRType(
    gpg::ReadArchive* archive, const std::initializer_list<const char*>& typeNames, const gpg::RRef& ownerRef
  )
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* expected = RequireRTypeByNameAny(typeNames);
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef casted = gpg::REF_UpcastPtr(source, expected);
    GPG_ASSERT(casted.mObj != nullptr);
    return casted.mObj ? casted.mObj : tracked.object;
  }

  /**
   * Address: 0x00744C90 (FUN_00744C90, func_ArchiveWriteLuaObj)
   *
   * What it does:
   * Writes all key/value lanes from one Lua table iterator into archive object
   * stream as `LuaObject` entries, then writes one trailing nil marker object.
   */
  LuaPlus::LuaObject* func_ArchiveWriteLuaObj(gpg::WriteArchive* const archive, LuaPlus::LuaObject* const tableObject)
  {
    if (!archive || !tableObject) {
      return tableObject;
    }

    gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
    if (!luaObjectType) {
      luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = luaObjectType;
    }

    gpg::RRef nullOwner{};
    for (LuaPlus::LuaTableIterator iter(tableObject, 1); !iter.m_isDone; iter.Next()) {
      archive->Write(luaObjectType, &iter.m_keyObj, nullOwner);
      archive->Write(luaObjectType, &iter.m_valueObj, nullOwner);
    }

    LuaPlus::LuaObject nilObject{};
    nilObject.AssignNil(tableObject->m_state);
    archive->Write(luaObjectType, &nilObject, nullOwner);
    return tableObject;
  }

  struct Rect2iVectorRuntimeView
  {
    void* allocatorProxy;
    gpg::Rect2i* first;
    gpg::Rect2i* last;
    gpg::Rect2i* end;
  };
  static_assert(sizeof(Rect2iVectorRuntimeView) == 0x10, "Rect2iVectorRuntimeView size must be 0x10");
  static_assert(offsetof(Rect2iVectorRuntimeView, first) == 0x04, "Rect2iVectorRuntimeView::first offset must be 0x04");
  static_assert(offsetof(Rect2iVectorRuntimeView, last) == 0x08, "Rect2iVectorRuntimeView::last offset must be 0x08");
  static_assert(offsetof(Rect2iVectorRuntimeView, end) == 0x0C, "Rect2iVectorRuntimeView::end offset must be 0x0C");

  struct SimSerMapDataRuntimeView
  {
    std::uint8_t reserved0000_08CB[0x8CC];
    STIMap* mapData;
    std::uint8_t reserved08D0_09F7[0x128];
    Rect2iVectorRuntimeView cachedMapRects;
    Rect2iVectorRuntimeView loadedMapRects;
  };
  static_assert(offsetof(SimSerMapDataRuntimeView, mapData) == 0x8CC, "Sim::mMapData offset must be 0x8CC");
  static_assert(
    offsetof(SimSerMapDataRuntimeView, cachedMapRects) == 0x9F8, "Sim cached map-rect vector offset must be 0x9F8"
  );
  static_assert(
    offsetof(SimSerMapDataRuntimeView, loadedMapRects) == 0xA08, "Sim loaded map-rect vector offset must be 0xA08"
  );

  struct PointerSlotCollectionRuntimeView
  {
    std::uint32_t reserved00;      // +0x00
    void** slots;                  // +0x04
    std::uint32_t slotCount;       // +0x08
    std::uint32_t ownerRefOrState; // +0x0C
    std::uint32_t pendingRefCount; // +0x10
  };
  static_assert(sizeof(PointerSlotCollectionRuntimeView) == 0x14, "PointerSlotCollectionRuntimeView size must be 0x14");
  static_assert(offsetof(PointerSlotCollectionRuntimeView, slots) == 0x04, "PointerSlotCollectionRuntimeView::slots offset must be 0x04");
  static_assert(
    offsetof(PointerSlotCollectionRuntimeView, slotCount) == 0x08,
    "PointerSlotCollectionRuntimeView::slotCount offset must be 0x08"
  );
  static_assert(
    offsetof(PointerSlotCollectionRuntimeView, ownerRefOrState) == 0x0C,
    "PointerSlotCollectionRuntimeView::ownerRefOrState offset must be 0x0C"
  );
  static_assert(
    offsetof(PointerSlotCollectionRuntimeView, pendingRefCount) == 0x10,
    "PointerSlotCollectionRuntimeView::pendingRefCount offset must be 0x10"
  );

  /**
   * Address: 0x0074DF10 (FUN_0074DF10, sub_74DF10)
   *
   * What it does:
   * Drains one pending-ref counter lane to zero (clearing owner lane at zero),
   * then deletes every non-null slot payload and frees the slot table storage.
   */
  // Invoked by ~Sim to drain the deletion-queue pending-ref lane.
  void DrainPendingRefsAndReleasePointerSlots(PointerSlotCollectionRuntimeView* const runtime) noexcept
  {
    while (runtime->pendingRefCount != 0u) {
      std::uint32_t count = runtime->pendingRefCount;
      if (count != 0u) {
        --count;
        runtime->pendingRefCount = count;
        if (count == 0u) {
          runtime->ownerRefOrState = 0u;
        }
      }
    }

    std::uint32_t index = runtime->slotCount;
    while (index > 0u) {
      --index;
      void* const slotPayload = runtime->slots[index];
      if (slotPayload != nullptr) {
        ::operator delete(slotPayload);
      }
    }

    if (runtime->slots != nullptr) {
      ::operator delete(runtime->slots);
    }

    runtime->slots = nullptr;
    runtime->slotCount = 0u;
  }

  /**
   * Address: 0x0074C940 (FUN_0074C940, sub_74C940)
   *
   * What it does:
   * Jump-thunk lane that forwards directly to `DrainPendingRefsAndReleasePointerSlots`.
   */
  [[maybe_unused]] void DrainPendingRefsAndReleasePointerSlotsThunk(PointerSlotCollectionRuntimeView* const runtime) noexcept
  {
    DrainPendingRefsAndReleasePointerSlots(runtime);
  }

  struct IntrusiveListNodeRuntimeView
  {
    IntrusiveListNodeRuntimeView* next; // +0x00
    IntrusiveListNodeRuntimeView* prev; // +0x04
  };
  static_assert(sizeof(IntrusiveListNodeRuntimeView) == 0x08, "IntrusiveListNodeRuntimeView size must be 0x08");

  struct IntrusiveListStorageRuntimeView
  {
    std::uint32_t reserved00;            // +0x00
    IntrusiveListNodeRuntimeView* head;  // +0x04
    std::uint32_t size;                  // +0x08
  };
  static_assert(sizeof(IntrusiveListStorageRuntimeView) == 0x0C, "IntrusiveListStorageRuntimeView size must be 0x0C");
  static_assert(
    offsetof(IntrusiveListStorageRuntimeView, head) == 0x04,
    "IntrusiveListStorageRuntimeView::head offset must be 0x04"
  );
  static_assert(
    offsetof(IntrusiveListStorageRuntimeView, size) == 0x08,
    "IntrusiveListStorageRuntimeView::size offset must be 0x08"
  );

  /**
   * Address: 0x00739F50 (FUN_00739F50, sub_739F50)
   *
   * What it does:
   * Resets one intrusive-list sentinel (`head->next=head`, `head->prev=head`),
   * clears size to zero, then deletes each former node until sentinel reached.
   */
  [[maybe_unused]] IntrusiveListNodeRuntimeView* ClearIntrusiveListAndResetHead(
    IntrusiveListStorageRuntimeView* const listRuntime
  ) noexcept
  {
    IntrusiveListNodeRuntimeView* const head = listRuntime->head;
    IntrusiveListNodeRuntimeView* node = head->next;
    head->next = head;
    head->prev = head;
    listRuntime->size = 0u;

    if (node != head) {
      do {
        IntrusiveListNodeRuntimeView* const next = node->next;
        ::operator delete(node);
        node = next;
      } while (node != head);
    }

    return node;
  }

  [[nodiscard]] gpg::RType* ResolveRect2iRType()
  {
    gpg::RType* rectType = gpg::Rect2i::sType;
    if (rectType == nullptr) {
      rectType = gpg::LookupRType(typeid(gpg::Rect2<int>));
      gpg::Rect2i::sType = rectType;
    }
    return rectType;
  }

  void SaveTaskStages(
    gpg::WriteArchive* archive,
    CTaskStage* stageA,
    CTaskStage* diskWatcherStage,
    CTaskStage* stageB,
    const gpg::RRef& ownerRef
  )
  {
    SaveObjectByRType(archive, stageA, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    SaveObjectByRType(archive, diskWatcherStage, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    SaveObjectByRType(archive, stageB, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
  }

  void LoadTaskStages(
    gpg::ReadArchive* archive,
    CTaskStage* stageA,
    CTaskStage* diskWatcherStage,
    CTaskStage* stageB,
    const gpg::RRef& ownerRef
  )
  {
    LoadObjectByRType(archive, stageA, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    LoadObjectByRType(archive, diskWatcherStage, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    LoadObjectByRType(archive, stageB, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
  }

  bool IsSimDebugCheatsEnabled()
  {
    return moho::console::SimDebugCheatsEnabled();
  }

  bool IsSimReportCheatsEnabled()
  {
    return moho::console::SimReportCheatsEnabled();
  }

  int GetCallStackFrames(unsigned int* outFrames)
  {
    return moho::console::PlatformGetCallStack(outFrames, 0x10u);
  }

  void FormatCallStack(msvc8::string* outText, const int frameCount, const unsigned int* frames)
  {
    moho::console::PlatformFormatCallstack(outText, frameCount, frames);
  }

  CSimConVarBase* PathBackgroundUpdateConVar()
  {
    return moho::console::SimPathBackgroundUpdateConVar();
  }

  CSimConVarBase* PathBackgroundBudgetConVar()
  {
    return moho::console::SimPathBackgroundBudgetConVar();
  }

  CSimConVarBase* ChecksumPeriodConVar()
  {
    return moho::console::SimChecksumPeriodConVar();
  }

  [[maybe_unused]] CSimConVarBase* PathTimeoutPreviewConVar()
  {
    return moho::console::SimPathTimeoutPreviewConVar();
  }

  struct PathPreviewFinderQueueOwnerRuntimeView
  {
    std::uint8_t mPad00_03[0x4];
    TDatListItem<void, void> mQueueHead; // +0x04, owned by CArmyImpl's still-unresolved PathQueue lane
  };
  static_assert(
    offsetof(PathPreviewFinderQueueOwnerRuntimeView, mQueueHead) == 0x4,
    "PathPreviewFinderQueueOwnerRuntimeView::mQueueHead offset"
  );

} // namespace

// `Moho::PathPreviewFinder` is forward-declared at real `moho::` scope in
// gpg/core/utils/BoostWrappers.h (for `boost::shared_ptr<PathPreviewFinder>`'s
// control-block instantiations) - it cannot live in the anonymous namespace
// used by the rest of this file's file-local helpers, so this cluster opens a
// real `namespace moho` block instead.
namespace moho
{
  /**
   * Preview-only `IPathTraveler` implementation used by `Sim::path_GeneratePreview`
   * (the `path_GeneratePreview` SimCon command) to run a background pathfind on
   * behalf of a UI drag-to-move preview.
   *
   * RTTI: vftable@0x00E35D5C, 12 primary slots (inherited from `Moho::IPathTraveler`,
   * `??_7PathPreviewFinder@Moho@@6B@`); bases `Moho::IPathTraveler` (mdisp=0),
   * `.?AV?$DListItem@VIPathTraveler@Moho@@X@gpg@@` (mdisp=4, modeled by
   * `IPathTraveler::mPathQueueNode`), `boost::noncopyable` (mdisp=4) - all already
   * covered by deriving from the already-recovered `Moho::IPathTraveler`.
   */
  class PathPreviewFinder final : public IPathTraveler
  {
  public:
    /**
     * Address: 0x007647E0 (FUN_007647E0, ??0PathPreviewFinder@Moho@@QAE@@Z)
     *
     * What it does:
     * Binds the finder to its owning army, resolves the owning `Sim`/`COGrid`
     * and the army's path-preview callback owner through `CArmyImpl::GetSim`/
     * `CArmyImpl::GetPathFinder`, and clears the active preview endpoints.
     */
    explicit PathPreviewFinder(CArmyImpl* owningArmy) noexcept;

    // Moho::IPathTraveler overrides (RTTI vftable slots 0-11).
    [[nodiscard]] const SFootprint* GetFootprint() const override;
    [[nodiscard]] bool CanTraverseCell(const SOCellPos& cellPos) const override;
    [[nodiscard]] bool IsInBounds(const SOCellPos& fromCell, const SOCellPos& toCell, float* edgeCost) const override;
    [[nodiscard]] float GetHeuristicCost(const SOCellPos& cellPos) const override;
    void GetAnchorCell(HPathCell* outCell) const override;
    [[nodiscard]] bool IsGoalCandidateCell(const SOCellPos& cellPos) const override;
    void OnPathAccepted(const SNavPath& path) override;
    [[nodiscard]] bool ShouldSearchRect(const gpg::Rect2i& rect) const override;
    void OnPathSearchCancelled() override;
    void OnPathRejected(const SNavPath& path) override;
    [[nodiscard]] std::int32_t GetPathcap() const override;
    void GetResultCell(HPathCell* outCell) const override;

    /**
     * Address: 0x00764880 (FUN_00764880)
     *
     * What it does:
     * Updates the preview finder start/goal lanes when footprint traversal state
     * changes, then requeues the finder at the front of the callback-owner list.
     */
    void ApplySearchEndpoints(const SFootprint* footprint, const SOCellPos& startCell, const SOCellPos& goalCell);

    /**
     * Address: 0x00764900 (FUN_00764900)
     *
     * What it does:
     * Detaches this finder from the callback-owner queue and clears its current
     * footprint lane, when a footprint is currently active.
     */
    void ResetQueuedFootprint();

  public:
    CArmyImpl* mOwnerContext;         // +0x0C
    Sim* mSim;                        // +0x10
    COGrid* mOGrid;                   // +0x14
    void* mPathPreviewCallbackOwner;  // +0x18 (CArmyImpl::GetPathFinder() result; still-unresolved PathQueue owner)
    SOCellPos mStartCell;             // +0x1C
    SOCellPos mGoalCell;              // +0x20
    const SFootprint* mFootprint;     // +0x24
    bool mStartCellIsTraversable;     // +0x28 (asm: OCCUPY_FootprintFits tested against mStartCell, not mGoalCell)
  };

  static_assert(offsetof(PathPreviewFinder, mOwnerContext) == 0x0C, "PathPreviewFinder::mOwnerContext offset");
  static_assert(offsetof(PathPreviewFinder, mSim) == 0x10, "PathPreviewFinder::mSim offset");
  static_assert(offsetof(PathPreviewFinder, mOGrid) == 0x14, "PathPreviewFinder::mOGrid offset");
  static_assert(offsetof(PathPreviewFinder, mPathPreviewCallbackOwner) == 0x18, "PathPreviewFinder::mPathPreviewCallbackOwner offset");
  static_assert(offsetof(PathPreviewFinder, mStartCell) == 0x1C, "PathPreviewFinder::mStartCell offset");
  static_assert(offsetof(PathPreviewFinder, mGoalCell) == 0x20, "PathPreviewFinder::mGoalCell offset");
  static_assert(offsetof(PathPreviewFinder, mFootprint) == 0x24, "PathPreviewFinder::mFootprint offset");
  static_assert(offsetof(PathPreviewFinder, mStartCellIsTraversable) == 0x28, "PathPreviewFinder::mStartCellIsTraversable offset");
  static_assert(sizeof(PathPreviewFinder) == 0x2C, "PathPreviewFinder size must be 0x2C");

  PathPreviewFinder::PathPreviewFinder(CArmyImpl* const owningArmy) noexcept
    : IPathTraveler()
    , mOwnerContext(owningArmy)
    , mSim(owningArmy->GetSim())
    , mOGrid(mSim->mOGrid)
    , mPathPreviewCallbackOwner(owningArmy->GetPathFinder())
    , mStartCell{0, 0}
    , mGoalCell{0, 0}
    , mFootprint(nullptr)
    , mStartCellIsTraversable(false)
  {
  }

  /**
   * Address: 0x007657D0 (FUN_007657D0)
   *
   * What it does:
   * Destroys one heap-allocated `PathPreviewFinder` by invoking its real
   * (implicit) destructor chain -- see `PathPreviewFinder.h` for the full
   * cross-emission evidence -- then releasing the allocation.
   */
  void DeletePathPreviewFinder(PathPreviewFinder* const finder) noexcept
  {
    delete finder;
  }
} // namespace moho

namespace
{
  /**
   * Address: 0x00763DC0 (FUN_00763DC0)
   * Address: 0x00764760 (FUN_00764760)
   *
   * What it does:
   * Copies one contiguous 32-bit lane range `[sourceBegin, sourceEnd)` into
   * destination storage and returns one-past the copied destination cursor.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeNullable(
    std::uint32_t* destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const std::uint32_t* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<std::uint32_t*>(destinationAddress) = *source;
      }
      destinationAddress += sizeof(std::uint32_t);
    }

    return reinterpret_cast<std::uint32_t*>(destinationAddress);
  }

  /**
   * Address: 0x00764610 (FUN_00764610)
   *
   * What it does:
   * Adapter lane that forwards one dword-range copy into the canonical
   * `CopyDwordRangeNullable` helper.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapterLaneA(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x007646F0 (FUN_007646F0)
   *
   * What it does:
   * Secondary adapter lane that forwards one dword-range copy into
   * `CopyDwordRangeNullable`.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapterLaneB(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00764720 (FUN_00764720)
   *
   * What it does:
   * Third adapter lane that forwards one dword-range copy into
   * `CopyDwordRangeNullable`.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapterLaneC(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }
} // namespace

namespace moho
{
  const SFootprint* PathPreviewFinder::GetFootprint() const
  {
    return mFootprint;
  }

  bool PathPreviewFinder::CanTraverseCell(const SOCellPos& cellPos) const
  {
    return static_cast<std::uint8_t>(
             OCCUPY_FootprintFits(*mOGrid, cellPos, *mFootprint, EOccupancyCaps::OC_ANY)
           ) != 0u;
  }

  // Address: 0x007647A0 (FUN_007647A0) -- always-in-bounds policy for preview traversal.
  bool PathPreviewFinder::IsInBounds(const SOCellPos&, const SOCellPos&, float*) const
  {
    return true;
  }

  float PathPreviewFinder::GetHeuristicCost(const SOCellPos& cellPos) const
  {
    const float deltaX = std::fabs(static_cast<float>(mGoalCell.x - cellPos.x));
    const float deltaZ = std::fabs(static_cast<float>(mGoalCell.z - cellPos.z));
    constexpr float kDiagScale = 0.41421354f;
    constexpr float kPreviewCostScale = 1.01f;
    const float baseCost = (deltaZ <= deltaX) ? ((deltaZ * kDiagScale) + deltaX) : ((deltaX * kDiagScale) + deltaZ);
    return baseCost * kPreviewCostScale;
  }

  // Address: 0x00764A00 (FUN_00764A00) -- writes the current preview anchor cell into the output lane.
  void PathPreviewFinder::GetAnchorCell(HPathCell* const outCell) const
  {
    outCell->x = static_cast<std::uint16_t>(mStartCell.x);
    outCell->z = static_cast<std::uint16_t>(mStartCell.z);
  }

  bool PathPreviewFinder::IsGoalCandidateCell(const SOCellPos& cellPos) const
  {
    return cellPos.x == mGoalCell.x && cellPos.z == mGoalCell.z;
  }

  /**
   * Address: 0x00764A80 (FUN_00764A80)
   *
   * What it does:
   * Publishes the accepted/rejected path's cells to the owning army through
   * `CArmyImpl::SetUnknownVectorWithMeta` (vtable slot +0x5C on the owner),
   * reusing the same generic word-vector-with-meta payload
   * (`Moho::SArmyVectorWithMeta`) `CArmyImpl` uses for its variable-data copy
   * lane: each 4-byte `SOCellPos` cell is packed into one `mWords` element and
   * the previous footprint pointer is carried in `mMetaWord`. Clears the
   * active footprint lane before publishing.
   */
  void PathPreviewFinder::OnPathAccepted(const SNavPath& path)
  {
    SArmyVectorWithMeta payload{};
    const std::size_t cellCount = path.Count();
    payload.mWords.resize(cellCount);
    for (std::size_t i = 0; i < cellCount; ++i) {
      payload.mWords[i] = std::bit_cast<std::uint32_t>(path.start[i]);
    }
    payload.mMetaWord = std::bit_cast<std::uint32_t>(mFootprint);
    mFootprint = nullptr;

    mOwnerContext->SetUnknownVectorWithMeta(&payload);
  }

  bool PathPreviewFinder::ShouldSearchRect(const gpg::Rect2i& rect) const
  {
    const auto inRect = [&rect](const SOCellPos& cell) {
      return cell.x >= rect.x0 && cell.x < rect.x1 && cell.z >= rect.z0 && cell.z < rect.z1;
    };
    return inRect(mStartCell) || inRect(mGoalCell);
  }

  // Address: 0x007647B0 (FUN_007647B0, nullsub_2211) -- no-op cancellation callback.
  void PathPreviewFinder::OnPathSearchCancelled()
  {
  }

  /**
   * Address: 0x00764B60 (FUN_00764B60)
   *
   * What it does:
   * The binary is a tail-call thunk (`jmp [[this]+0x18]`) into this finder's
   * own `OnPathAccepted` vtable slot, i.e. a rejected search publishes the
   * same cell payload as an accepted one.
   */
  void PathPreviewFinder::OnPathRejected(const SNavPath& path)
  {
    OnPathAccepted(path);
  }

  /**
   * Address: 0x00764B70 (FUN_00764B70)
   *
   * What it does:
   * Reads the current `path_TimeoutPreview` sim-convar value from the owning
   * sim lane used by path-preview traversal callbacks.
   */
  std::int32_t PathPreviewFinder::GetPathcap() const
  {
    CSimConVarInstanceBase* const instance = mSim->GetSimVar(PathTimeoutPreviewConVar());
    return *reinterpret_cast<const std::int32_t*>(instance->GetValueStorage());
  }

  // Address: 0x007647D0 (FUN_007647D0) -- clears one output result-cell lane.
  void PathPreviewFinder::GetResultCell(HPathCell* const outCell) const
  {
    outCell->x = 0;
    outCell->z = 0;
  }

  void PathPreviewFinder::ApplySearchEndpoints(
    const SFootprint* const footprint,
    const SOCellPos& startCell,
    const SOCellPos& goalCell
  )
  {
    if (mFootprint == footprint && mStartCellIsTraversable) {
      return;
    }

    mStartCell = startCell;
    mGoalCell = goalCell;
    mFootprint = footprint;
    // asm evidence (0x007648A9-0x007648B7): OCCUPY_FootprintFits is tested
    // against the just-assigned mStartCell, not mGoalCell.
    mStartCellIsTraversable =
      static_cast<std::uint8_t>(OCCUPY_FootprintFits(*mOGrid, mStartCell, *footprint, EOccupancyCaps::OC_ANY)) != 0u;

    mPathQueueNode.ListUnlink();
    auto* const ownerSlot = reinterpret_cast<PathPreviewFinderQueueOwnerRuntimeView**>(mPathPreviewCallbackOwner);
    if (ownerSlot != nullptr && *ownerSlot != nullptr) {
      mPathQueueNode.ListLinkAfter(&(*ownerSlot)->mQueueHead);
    }
  }

  void PathPreviewFinder::ResetQueuedFootprint()
  {
    if (mFootprint == nullptr) {
      return;
    }

    mPathQueueNode.ListUnlink();
    mFootprint = nullptr;
  }
} // namespace moho

namespace
{
  struct PathPreviewUnitSetRuntimeView
  {
    std::uint8_t mPad00_07[0x8];
    void** mUnitBegin;
    void** mUnitEnd;
  };
  static_assert(offsetof(PathPreviewUnitSetRuntimeView, mUnitBegin) == 0x8, "PathPreviewUnitSetRuntimeView::mUnitBegin");
  static_assert(offsetof(PathPreviewUnitSetRuntimeView, mUnitEnd) == 0xC, "PathPreviewUnitSetRuntimeView::mUnitEnd");
  static_assert(offsetof(SEntitySetTemplateUnit, mVec) == 0x08, "SEntitySetTemplateUnit::mVec offset must alias PathPreviewUnitSetRuntimeView::mUnitBegin");

  [[nodiscard]] Unit* PathPreviewUnitFromSetHandle(void* const handle)
  {
    if (!handle) {
      return nullptr;
    }

    // Unit-set handles retain an interior pointer; binary lane normalizes by -8.
    // (Not `SEntitySetTemplateUnit::UnitFromEntry`'s `IsUnit()` dispatch: the
    // asm at 0x00764B9A-0x00764BA6 does the raw pointer-minus-8 directly.)
    auto* const bytes = reinterpret_cast<std::uint8_t*>(handle);
    return reinterpret_cast<Unit*>(bytes - 0x8);
  }

  /**
   * Address: 0x00764B90 (FUN_00764B90)
   *
   * What it does:
   * Chooses one live unit from the candidate unit-set lane that has a resolved
   * footprint and the largest blueprint size-Z lane.
   */
  Unit* PathPreviewSelectLargestUnit(const SEntitySetTemplateUnit* const unitSet)
  {
    if (!unitSet) {
      return nullptr;
    }

    const auto* const view = reinterpret_cast<const PathPreviewUnitSetRuntimeView*>(unitSet);
    void** unitIt = view->mUnitBegin;
    if (unitIt == view->mUnitEnd) {
      return nullptr;
    }

    Unit* bestUnit = nullptr;
    float bestSizeZ = 0.0f;
    while (unitIt != view->mUnitEnd) {
      Unit* const unit = PathPreviewUnitFromSetHandle(*unitIt);
      ++unitIt;
      if (!unit) {
        continue;
      }

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (!blueprint || !blueprint->Physics.ResolvedFootprint || unit->IsBeingBuilt()) {
        continue;
      }

      if (blueprint->mSizeZ > bestSizeZ) {
        bestSizeZ = blueprint->mSizeZ;
        bestUnit = unit;
      }
    }

    return bestUnit;
  }

  struct PathPreviewUnitRuntimeView
  {
    std::uint8_t mPad00_4B3[0x4B4];
    CUnitCommandQueue* mCommandQueue;
    std::uint8_t mPad4B8_553[0x9C];
    void* mPreviewTargetProvider;
  };
  static_assert(offsetof(PathPreviewUnitRuntimeView, mCommandQueue) == 0x4B4, "PathPreviewUnitRuntimeView::mCommandQueue");
  static_assert(
    offsetof(PathPreviewUnitRuntimeView, mPreviewTargetProvider) == 0x554,
    "PathPreviewUnitRuntimeView::mPreviewTargetProvider"
  );

  struct PathPreviewTargetEntryRuntimeView
  {
    void* mTargetHandle;
    void* mPad04;
  };
  static_assert(sizeof(PathPreviewTargetEntryRuntimeView) == 0x8, "PathPreviewTargetEntryRuntimeView size must be 0x8");

  struct PathPreviewTargetQueueRuntimeView
  {
    void* mProxy;
    PathPreviewTargetEntryRuntimeView* mBegin;
    PathPreviewTargetEntryRuntimeView* mEnd;
  };
  static_assert(sizeof(PathPreviewTargetQueueRuntimeView) == 0x0C, "PathPreviewTargetQueueRuntimeView size must be 0x0C");

  struct PathPreviewTargetProviderRuntimeView;
  struct PathPreviewTargetProviderVTableRuntimeView
  {
    void* mSlots00_1C[0x8];
    PathPreviewTargetQueueRuntimeView* (__thiscall* GetTargetQueue)(PathPreviewTargetProviderRuntimeView* owner);
  };
  static_assert(
    offsetof(PathPreviewTargetProviderVTableRuntimeView, GetTargetQueue) == 0x20,
    "PathPreviewTargetProviderVTableRuntimeView::GetTargetQueue offset"
  );

  struct PathPreviewTargetProviderRuntimeView
  {
    PathPreviewTargetProviderVTableRuntimeView* mVTable;
  };

  struct PathPreviewTargetRuntimeView
  {
    std::uint8_t mPad00_97[0x98];
    std::int32_t mTargetTypeIndex;
    std::uint8_t mPad9C_11B[0x80];
    CAiTarget mTarget;
  };
  static_assert(offsetof(PathPreviewTargetRuntimeView, mTargetTypeIndex) == 0x98, "PathPreviewTargetRuntimeView::mTargetTypeIndex");
  static_assert(offsetof(PathPreviewTargetRuntimeView, mTarget) == 0x11C, "PathPreviewTargetRuntimeView::mTarget");

  [[nodiscard]] PathPreviewTargetRuntimeView* PathPreviewTargetFromHandle(void* const handle)
  {
    if (!handle) {
      return nullptr;
    }

    auto* const bytes = reinterpret_cast<std::uint8_t*>(handle);
    return reinterpret_cast<PathPreviewTargetRuntimeView*>(bytes - 0x4);
  }

  [[nodiscard]] bool PathPreviewTargetTypeFiltered(const std::int32_t targetTypeIndex)
  {
    if (targetTypeIndex < 0 || targetTypeIndex >= 32) {
      return true;
    }

    constexpr std::uint32_t kFilteredTargetMask = 0xD80000EAu;
    return (kFilteredTargetMask & (1u << targetTypeIndex)) != 0u;
  }

  [[nodiscard]] const PathPreviewTargetQueueRuntimeView* PathPreviewResolveTargetQueue(const Unit* const unit)
  {
    const auto* const unitView = reinterpret_cast<const PathPreviewUnitRuntimeView*>(unit);
    if (unitView->mPreviewTargetProvider) {
      auto* const provider = reinterpret_cast<PathPreviewTargetProviderRuntimeView*>(unitView->mPreviewTargetProvider);
      auto* const providerVTable = provider->mVTable;
      if (providerVTable && providerVTable->GetTargetQueue) {
        PathPreviewTargetQueueRuntimeView* const queue = providerVTable->GetTargetQueue(provider);
        if (queue && queue->mBegin && queue->mBegin != queue->mEnd) {
          return queue;
        }
      }
    }

    if (!unitView->mCommandQueue) {
      return nullptr;
    }

    const auto* const commandQueueBytes = reinterpret_cast<const std::uint8_t*>(unitView->mCommandQueue);
    return reinterpret_cast<const PathPreviewTargetQueueRuntimeView*>(commandQueueBytes + 0x0C);
  }

  /**
   * Address: 0x00764C10 (FUN_00764C10)
   *
   * What it does:
   * Chooses one terminal target position from queued command-target handles
   * (walking newest-to-oldest), then falls back to the unit position lane.
   */
  Wm3::Vector3f* PathPreviewResolveEndPosition(Wm3::Vector3f* const outPos, Unit* const unit)
  {
    const PathPreviewTargetQueueRuntimeView* const targetQueue = PathPreviewResolveTargetQueue(unit);
    if (targetQueue && targetQueue->mBegin && targetQueue->mBegin != targetQueue->mEnd) {
      auto* entry = targetQueue->mEnd;
      while (entry != targetQueue->mBegin) {
        --entry;
        PathPreviewTargetRuntimeView* const targetRuntime = PathPreviewTargetFromHandle(entry->mTargetHandle);
        if (!targetRuntime) {
          continue;
        }

        if (PathPreviewTargetTypeFiltered(targetRuntime->mTargetTypeIndex)) {
          continue;
        }

        const Wm3::Vec3f targetPos = targetRuntime->mTarget.GetTargetPosGun(false);
        outPos->x = targetPos.x;
        outPos->y = targetPos.y;
        outPos->z = targetPos.z;
        return outPos;
      }
    }

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    outPos->x = unitPos.x;
    outPos->y = unitPos.y;
    outPos->z = unitPos.z;
    return outPos;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00764CF0 (FUN_00764CF0, Moho::Sim::path_GeneratePreview)
   *
   * IDA signature:
   * void __cdecl Moho::Sim::path_GeneratePreview(
   *   Moho::Sim* sim, std::vector<std::string>* commandArgs, Wm3::Vector3f* worldPos,
   *   Moho::CArmyImpl* focusArmy, Moho::SEntitySetTemplateUnit* selectedUnits);
   *
   * What it does:
   * `path_GeneratePreview` SimCon command. Picks the largest selected unit with
   * a resolved footprint that isn't being built; if one exists, lazily creates
   * (or reuses) the army's cached `PathPreviewFinder`, resolves the search
   * start cell (the unit's current position, or its queued end-of-command
   * target when the command's second argument is `"end"`) and goal cell (the
   * mouse world position) footprint-centered, and applies them to the finder.
   * If no eligible unit is selected, clears any cached preview finder and its
   * published-path payload on the army. Every branch feeds the desync MD5
   * hash and mirrors it to the sim log, matching the binary exactly so replay
   * checksums stay reproducible.
   */
  int Sim::path_GeneratePreview(
    Sim* const sim,
    CSimConCommand::ParsedCommandArgs* const commandArgs,
    Wm3::Vector3f* const worldPos,
    CArmyImpl* const focusArmy,
    SEntitySetTemplateUnit* const selectedUnits
  )
  {
    if (focusArmy == nullptr) {
      return 0;
    }

    SSTIArmyConstantData armyConstData{};
    focusArmy->CopyArmyConstantData(&armyConstData);
    sim->mContext.Update(&armyConstData.mArmyIndex, sizeof(armyConstData.mArmyIndex));
    sim->Logf("path preview for army %d\n", armyConstData.mArmyIndex);

    boost::shared_ptr<PathPreviewFinder> previewFinder{};
    focusArmy->GetUnknownSharedRef(reinterpret_cast<boost::SharedPtrRaw<void>*>(&previewFinder));

    Unit* const unit = PathPreviewSelectLargestUnit(selectedUnits);
    if (unit != nullptr) {
      // Binary logs/hashes a still-unresolved Unit diagnostic dword at +0x70
      // (asm: `mov ecx, [esi+70h]` at 0x00764D7C) as "unit=0x%08x".
      struct PreviewUnitDiagnosticView
      {
        std::uint8_t mPad00_6F[0x70];
        std::uint32_t field_0x70;
      };
      static_assert(offsetof(PreviewUnitDiagnosticView, field_0x70) == 0x70, "PreviewUnitDiagnosticView::field_0x70 offset");
      const std::uint32_t unitDiagnostic = reinterpret_cast<const PreviewUnitDiagnosticView*>(unit)->field_0x70;
      sim->mContext.Update(&unitDiagnostic, sizeof(unitDiagnostic));
      sim->Logf("  unit=0x%08x\n", unitDiagnostic);

      if (!previewFinder) {
        previewFinder = boost::shared_ptr<PathPreviewFinder>(new PathPreviewFinder(focusArmy));
        focusArmy->SetUnknownSharedRef(reinterpret_cast<boost::SharedPtrRaw<void>*>(&previewFinder));
      }

      Wm3::Vector3f resolvedEndPos{};
      const bool wantsEndPosition =
        commandArgs->size() > 1 && (*commandArgs)[1] == "end";
      const Wm3::Vector3f& sourcePos = wantsEndPosition
        ? *PathPreviewResolveEndPosition(&resolvedEndPos, unit)
        : unit->GetPosition();

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      const SFootprint* const footprint = blueprint->Physics.ResolvedFootprint;
      const float halfSizeX = footprint->mSizeX * 0.5f;
      const float halfSizeZ = footprint->mSizeZ * 0.5f;

      SOCellPos start{};
      start.x = static_cast<std::int16_t>(sourcePos.x - halfSizeX);
      start.z = static_cast<std::int16_t>(sourcePos.z - halfSizeZ);

      SOCellPos goal{};
      goal.x = static_cast<std::int16_t>(worldPos->x - halfSizeX);
      goal.z = static_cast<std::int16_t>(worldPos->z - halfSizeZ);

      sim->mContext.Update(worldPos, sizeof(*worldPos));
      sim->Logf("  mousePos=<%f,%f,%f>\n", worldPos->x, worldPos->y, worldPos->z);
      sim->mContext.Update(&start, sizeof(start));
      sim->Logf("  start=<%d,%d>\n", start.x, start.z);
      sim->mContext.Update(&goal, sizeof(goal));
      sim->Logf("  goal=<%d,%d>\n", goal.x, goal.z);

      previewFinder->ApplySearchEndpoints(footprint, start, goal);
    } else {
      const std::int32_t noUnitSentinel = -1;
      sim->mContext.Update(&noUnitSentinel, sizeof(noUnitSentinel));
      sim->Logf("  no unit\n");

      if (previewFinder) {
        previewFinder->ResetQueuedFootprint();

        boost::shared_ptr<PathPreviewFinder> clearedFinder{};
        focusArmy->SetUnknownSharedRef(reinterpret_cast<boost::SharedPtrRaw<void>*>(&clearedFinder));

        SArmyVectorWithMeta clearedPayload{};
        focusArmy->SetUnknownVectorWithMeta(&clearedPayload);
      }
    }

    return 0;
  }
} // namespace moho

namespace
{
  bool IsDebugWindowEnabled()
  {
    return moho::SCR_IsDebugWindowActive();
  }

  lua_Hook GetDebugLuaHook()
  {
    return &moho::DebugLuaHook;
  }

  void RulesUpdateLuaState(RRuleGameRules* rules, LuaPlus::LuaState* luaState)
  {
    if (!rules) {
      return;
    }

    rules->UpdateLuaState(luaState);
  }

  void* GetSimVarStorage(CSimConVarInstanceBase* instance)
  {
    if (!instance) {
      return nullptr;
    }

    return instance->GetValueStorage();
  }

  bool ReadSimConVarBool(Sim* sim, CSimConVarBase* conVar, const bool defaultValue)
  {
    auto* instance = sim ? sim->GetSimVar(conVar) : nullptr;
    void* valuePtr = GetSimVarStorage(instance);
    if (!valuePtr) {
      return defaultValue;
    }
    return *reinterpret_cast<const uint8_t*>(valuePtr) != 0;
  }

  int ReadSimConVarInt(Sim* sim, CSimConVarBase* conVar, const int defaultValue)
  {
    auto* instance = sim ? sim->GetSimVar(conVar) : nullptr;
    void* valuePtr = GetSimVarStorage(instance);
    if (!valuePtr) {
      return defaultValue;
    }
    return *reinterpret_cast<const int*>(valuePtr);
  }

  void TickTaskStage(CTaskStage* stage)
  {
    if (!stage) {
      return;
    }

    stage->UserFrame();
  }

  void UpdatePaths(PathTables* pathTables, const int budget)
  {
    if (!pathTables) {
      return;
    }

    int pathBudget = budget;
    pathTables->UpdateBackground(&pathBudget);
  }

  template <typename Fn>
  void ForEachAllArmyUnit(CEntityDb* entityDb, Fn&& fn)
  {
    if (!entityDb) {
      return;
    }

    // 0x006B6AA0 / 0x005C87A0 iterate all army units in retail.
    // In source we walk the typed entity DB and keep only Unit owners.
    for (Entity* entity : entityDb->Entities()) {
      if (!entity) {
        continue;
      }

      Unit* unit = entity->IsUnit();
      if (!unit) {
        continue;
      }

      fn(unit);
    }
  }

  [[nodiscard]] bool TryParseArmyIndexArg(const std::string& text, std::size_t& outIndex) noexcept
  {
    if (text.empty()) {
      return false;
    }

    char* end = nullptr;
    const long parsed = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || (end && *end != '\0') || parsed < 0) {
      return false;
    }

    outIndex = static_cast<std::size_t>(parsed);
    return true;
  }

  template <typename THandler>
  void ForEachTargetArmyUnit(
    Sim* const sim, const CSimConCommand::ParsedCommandArgs* const commandArgs, THandler&& handler
  )
  {
    if (!sim || !sim->mEntityDB) {
      return;
    }

    const bool hasArmyFilters = commandArgs && commandArgs->size() > 1u;
    std::vector<std::size_t> targetArmyIndices;
    if (hasArmyFilters) {
      targetArmyIndices.reserve(commandArgs->size() - 1u);
      for (std::size_t argIndex = 1u; argIndex < commandArgs->size(); ++argIndex) {
        std::size_t parsedIndex = 0u;
        if (!TryParseArmyIndexArg((*commandArgs)[argIndex], parsedIndex)) {
          continue;
        }

        if (parsedIndex >= sim->mArmiesList.size()) {
          continue;
        }

        CArmyImpl* const army = sim->mArmiesList[parsedIndex];
        if (!army) {
          continue;
        }

        if (std::find(targetArmyIndices.begin(), targetArmyIndices.end(), parsedIndex) == targetArmyIndices.end()) {
          targetArmyIndices.push_back(parsedIndex);
        }
      }

      if (targetArmyIndices.empty()) {
        return;
      }
    }

    ForEachAllArmyUnit(sim->mEntityDB, [&](Unit* const unit) {
      if (!unit || !unit->ArmyRef) {
        return;
      }

      if (hasArmyFilters) {
        const std::size_t armyIndex = static_cast<std::size_t>(unit->ArmyRef->ArmyId);
        if (std::find(targetArmyIndices.begin(), targetArmyIndices.end(), armyIndex) == targetArmyIndices.end()) {
          return;
        }
      }

      handler(*unit);
    });
  }

  enum class PurgeCategory : std::uint8_t
  {
    All = 0u,
    Projectile = 1u,
    Unit = 2u,
    Shield = 3u,
    Other = 4u,
    Prop = 5u,
    Unknown = 0xFFu
  };

  [[nodiscard]] PurgeCategory ParsePurgeCategory(const std::string& token)
  {
    const char* const text = token.c_str();
    if (gpg::STR_EqualsNoCase(text, "all") || gpg::STR_StartsWithNoCase(text, "entity")) {
      return PurgeCategory::All;
    }
    if (gpg::STR_StartsWithNoCase(text, "projectile")) {
      return PurgeCategory::Projectile;
    }
    if (gpg::STR_StartsWithNoCase(text, "unit")) {
      return PurgeCategory::Unit;
    }
    if (gpg::STR_StartsWithNoCase(text, "shield")) {
      return PurgeCategory::Shield;
    }
    if (gpg::STR_StartsWithNoCase(text, "other")) {
      return PurgeCategory::Other;
    }
    if (gpg::STR_StartsWithNoCase(text, "prop")) {
      return PurgeCategory::Prop;
    }
    return PurgeCategory::Unknown;
  }

  [[nodiscard]] bool EntityMatchesPurgeCategory(const Entity& entity, const PurgeCategory category)
  {
    Entity& mutableEntity = const_cast<Entity&>(entity);
    switch (category) {
    case PurgeCategory::All:
      return true;
    case PurgeCategory::Projectile:
      return mutableEntity.IsProjectile() != nullptr;
    case PurgeCategory::Unit:
      return mutableEntity.IsUnit() != nullptr;
    case PurgeCategory::Shield:
      return mutableEntity.IsShield() != nullptr;
    case PurgeCategory::Prop:
      return mutableEntity.IsProp() != nullptr;
    case PurgeCategory::Other:
      return mutableEntity.IsUnit() == nullptr && mutableEntity.IsProjectile() == nullptr &&
        mutableEntity.IsShield() == nullptr && mutableEntity.IsProp() == nullptr;
    default:
      return false;
    }
  }

  [[nodiscard]] bool EntityMatchesPurgeArmyFilter(const Entity& entity, const int armyFilter) noexcept
  {
    if (armyFilter < 0) {
      return true;
    }

    const auto armyIndex = static_cast<std::uint8_t>(armyFilter & 0xFF);
    return ExtractEntityIdSourceIndex(static_cast<std::uint32_t>(entity.id_)) == armyIndex;
  }

  [[nodiscard]] bool ShouldDestroyEntityForPurge(const Entity& entity) noexcept
  {
    return entity.Dead == 0u && entity.DestroyQueuedFlag == 0u && entity.mOnDestroyDispatched == 0u;
  }

  void TickEffectManager(CEffectManagerImpl* effectManager)
  {
    if (!effectManager) {
      return;
    }

    effectManager->Tick();
  }

  void PurgeDestroyedEffects(CEffectManagerImpl* effectManager)
  {
    if (!effectManager) {
      return;
    }

    effectManager->PurgeDestroyedEffects();
  }

  void UpdateFormationDb(CAiFormationDBImpl* formationDb)
  {
    if (!formationDb) {
      return;
    }

    formationDb->Update();
  }

  void AdvanceCoords(Entity* entity)
  {
    if (!entity) {
      return;
    }

    entity->AdvanceCoords();
  }

  void RunQueuedDestroy(void* queuedObject)
  {
    if (!queuedObject) {
      return;
    }

    Entity* entity = static_cast<Entity*>(queuedObject);
    entity->OnDestroy();
  }

  void CleanupDecals(CDecalBuffer* decalBuffer)
  {
    if (decalBuffer) {
      decalBuffer->CleanupTick();
    }
  }

  using DebugOverlayClassLink = TDatListItem<RDebugOverlayClass, void>;
  using DebugOverlayLink = TDatListItem<RDebugOverlay, void>;

  [[nodiscard]] RDebugOverlayClass* DebugOverlayClassFromLink(DebugOverlayClassLink* const link) noexcept
  {
    if (link == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<RDebugOverlayClass*>(
      reinterpret_cast<std::uint8_t*>(link) - offsetof(RDebugOverlayClass, mOverlayClassLink)
    );
  }

  [[nodiscard]] const RDebugOverlayClass* DebugOverlayClassFromLink(const DebugOverlayClassLink* const link) noexcept
  {
    if (link == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<const RDebugOverlayClass*>(
      reinterpret_cast<const std::uint8_t*>(link) - offsetof(RDebugOverlayClass, mOverlayClassLink)
    );
  }

  [[nodiscard]] gpg::RType* TryFindExactDebugOverlayType(const std::string& requestedName) noexcept
  {
    DebugOverlayClassLink* const overlays = GetDbgOverlays();
    if (overlays == nullptr) {
      return nullptr;
    }

    for (DebugOverlayClassLink* link = overlays->mPrev; link != overlays; link = link->mPrev) {
      const RDebugOverlayClass* const overlayClass = DebugOverlayClassFromLink(link);
      if (overlayClass == nullptr) {
        continue;
      }

      const char* const overlayName = overlayClass->mOverlayToken.c_str();
      if (overlayName != nullptr && gpg::STR_CompareNoCase(overlayName, requestedName.c_str()) == 0) {
        return const_cast<RDebugOverlayClass*>(overlayClass);
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00652060 (FUN_00652060, std::vector<const RDebugOverlayClass*>::push_back)
   *
   * What it does:
   * Per-T canonical-template-helper binding for the engine-instantiated
   * `std::vector<const RDebugOverlayClass*>::push_back(const&)` fast/slow-path
   * body (4-byte element stride: raw pointer). Rewiring the inline
   * `outMatches.push_back(overlayClass);` site through this helper preserves
   * the MSVC8 per-T template emission symbol shape.
   */
  void PushBackDebugOverlayClassPtrVector(
    std::vector<const RDebugOverlayClass*>& destination,
    const RDebugOverlayClass* const value)
  {
    destination.push_back(value);
  }

  void CollectPrefixDebugOverlayTypes(
    const std::string& requestedName,
    std::vector<const RDebugOverlayClass*>& outMatches
  )
  {
    DebugOverlayClassLink* const overlays = GetDbgOverlays();
    if (overlays == nullptr) {
      return;
    }

    for (DebugOverlayClassLink* link = overlays->mPrev; link != overlays; link = link->mPrev) {
      const RDebugOverlayClass* const overlayClass = DebugOverlayClassFromLink(link);
      if (overlayClass == nullptr) {
        continue;
      }

      const char* const overlayName = overlayClass->mOverlayToken.c_str();
      if (overlayName != nullptr && gpg::STR_StartsWithNoCase(overlayName, requestedName.c_str())) {
        PushBackDebugOverlayClassPtrVector(outMatches, overlayClass);
      }
    }
  }

  void PrintAvailableDebugOverlayList(Sim& sim)
  {
    sim.Printf(kDbgAvailableOverlaysText);

    DebugOverlayClassLink* const overlays = GetDbgOverlays();
    if (overlays == nullptr) {
      return;
    }

    for (DebugOverlayClassLink* link = overlays->mPrev; link != overlays; link = link->mPrev) {
      const RDebugOverlayClass* const overlayClass = DebugOverlayClassFromLink(link);
      if (overlayClass == nullptr) {
        continue;
      }

      sim.Printf("  %s - %s", overlayClass->GetName(), overlayClass->mOverlayDescription.c_str());
    }
  }

  [[nodiscard]] RDebugOverlay* FindDebugOverlayInstanceByType(Sim& sim, const gpg::RType& overlayType) noexcept
  {
    for (DebugOverlayLink* link = sim.mDebugOverlays.mPrev; link != &sim.mDebugOverlays; link = link->mPrev) {
      RDebugOverlay* const overlay = static_cast<RDebugOverlay*>(link);
      if (overlay != nullptr && overlay->GetClass() == &overlayType) {
        return overlay;
      }
    }

    return nullptr;
  }

  [[nodiscard]] RDebugOverlay* CreateDebugOverlayInstance(gpg::RType& overlayType)
  {
    return RDebugOverlay::NewPtr(overlayType);
  }

  void LinkDebugOverlayFront(Sim& sim, RDebugOverlay& overlay)
  {
    auto* const overlayLink = static_cast<DebugOverlayLink*>(&overlay);
    overlayLink->ListLinkAfter(&sim.mDebugOverlays);
  }

  void RemoveDebugOverlayInstance(RDebugOverlay& overlay)
  {
    auto* const overlayLink = static_cast<DebugOverlayLink*>(&overlay);
    overlayLink->ListUnlink();
    delete &overlay;
  }

  void TickDebugOverlay(RDebugOverlay* overlay, Sim* sim)
  {
    if (!overlay || !sim) {
      return;
    }
    overlay->Tick(sim);
  }
} // namespace

namespace moho
{
  [[nodiscard]] CUnitCommand* IssueFactoryCommandToSelectedUnits(
    Sim* const sim,
    const SEntitySetTemplateUnit& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    return ::IssueFactoryCommandToSelectedUnitsImpl(sim, selectedUnits, commandIssueData, clearQueue);
  }

  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnits(
    Sim* const sim,
    SEntitySetTemplateUnit& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    return ::IssueCommandToSelectedUnitsImpl(sim, selectedUnits, commandIssueData, clearQueue);
  }

  [[nodiscard]] RUnitBlueprint* ResolveUnitBlueprintFromLuaArgument(
    LuaPlus::LuaState* const state,
    const LuaPlus::LuaStackObject& blueprintObject,
    const char* const functionName
  )
  {
    return ::ResolveUnitBlueprintFromLuaArgumentImpl(state, blueprintObject, functionName);
  }

  /**
   * Address: 0x008B4720 (FUN_008B4720, sub_8B4720)
   *
   * What it does:
   * Public entry point (declared in UserUnit.h) that appends a "select unit"
   * local update event into `helper`'s ring queue when needed, then inserts
   * `unit` into that event's weak-set. Forwards to
   * QueueCommandIssueSelectUnitEventImpl.
   */
  void QueueCommandIssueSelectUnitEvent(UserCommandIssueHelper* const helper, const CmdId cmdId, UserUnit* const unit)
  {
    ::QueueCommandIssueSelectUnitEventImpl(*helper, cmdId, unit);
  }

  /**
   * Address: 0x008B4880 (FUN_008B4880, sub_8B4880)
   *
   * What it does:
   * Public entry point (declared in UserUnit.h) that appends a "deselect
   * unit" local update event into `helper`'s ring queue when needed, then
   * inserts `unit` into that event's weak-set. Forwards to
   * QueueCommandIssueDeselectUnitEventImpl.
   */
  void QueueCommandIssueDeselectUnitEvent(UserCommandIssueHelper* const helper, const CmdId cmdId, UserUnit* const unit)
  {
    ::QueueCommandIssueDeselectUnitEventImpl(*helper, cmdId, unit);
  }
} // namespace moho

extern "C" gpg::Rect2i* Rect2CopyRange(const gpg::Rect2i* first, const gpg::Rect2i* last, gpg::Rect2i* destination);

/**
 * Address: 0x0074D930 (FUN_0074D930, sub_74D930)
 *
 * What it does:
 * Resizes one `Rect2i` vector-runtime lane to `count` elements:
 * - shrinks by moving the logical end lane when current size is larger;
 * - grows by appending `defaultValue` rectangles, allocating/reallocating
 *   backing storage when capacity is insufficient.
 */
extern "C" void Rect2VectorResizeDefault(
  const std::uint32_t count,
  void* const vectorStorage,
  const gpg::Rect2i* const defaultValue,
  const int /*reserved0*/,
  const int /*reserved1*/,
  const int /*reserved2*/
)
{
  auto* const runtime = static_cast<Rect2iVectorRuntimeView*>(vectorStorage);
  gpg::Rect2i* const begin = runtime->first;
  const std::uint32_t currentCount =
    (begin != nullptr) ? static_cast<std::uint32_t>(runtime->last - begin) : 0u;

  if (currentCount >= count) {
    if (begin != nullptr && count < currentCount) {
      runtime->last = begin + count;
    }
    return;
  }

  const gpg::Rect2i fillValue = (defaultValue != nullptr) ? *defaultValue : gpg::Rect2i{};
  const std::uint32_t appendCount = count - currentCount;

  if (begin == nullptr) {
    if (count == 0u) {
      runtime->last = runtime->first;
      runtime->end = runtime->first;
      return;
    }

    auto* const storage = static_cast<gpg::Rect2i*>(::operator new(static_cast<std::size_t>(count) * sizeof(gpg::Rect2i)));
    for (std::uint32_t index = 0u; index < count; ++index) {
      storage[index] = fillValue;
    }

    runtime->first = storage;
    runtime->last = storage + count;
    runtime->end = storage + count;
    return;
  }

  const std::uint32_t capacityCount = static_cast<std::uint32_t>(runtime->end - runtime->first);
  if (count > capacityCount) {
    std::uint32_t newCapacity = capacityCount + (capacityCount >> 1u);
    if (newCapacity < count) {
      newCapacity = count;
    }

    auto* const newStorage =
      static_cast<gpg::Rect2i*>(::operator new(static_cast<std::size_t>(newCapacity) * sizeof(gpg::Rect2i)));
    (void)Rect2CopyRange(runtime->first, runtime->last, newStorage);
    ::operator delete(runtime->first);

    runtime->first = newStorage;
    runtime->last = newStorage + currentCount;
    runtime->end = newStorage + newCapacity;
  }

  gpg::Rect2i* cursor = runtime->last;
  for (std::uint32_t index = 0u; index < appendCount; ++index, ++cursor) {
    *cursor = fillValue;
  }
  runtime->last = cursor;
}

/**
 * Address: 0x0074BFA0 (FUN_0074BFA0)
 *
 * What it does:
 * Stdcall adapter lane that forwards `(vectorStorage, count)` into
 * `Rect2VectorResizeDefault` with null default-fill and zeroed reserved lanes.
 */
[[maybe_unused]] void __stdcall Rect2VectorResizeDefaultStdcallAdapter(
  void* const vectorStorage,
  const std::uint32_t count
)
{
  Rect2VectorResizeDefault(count, vectorStorage, nullptr, 0, 0, 0);
}

extern "C"
/**
 * Address: 0x00753860 (FUN_00753860, sub_753860)
 *
 * What it does:
 * Copies one contiguous half-open `Rect2i` range `[first,last)` into
 * `destination` and returns one-past the copied destination cursor.
 */
gpg::Rect2i* Rect2CopyRange(const gpg::Rect2i* first, const gpg::Rect2i* last, gpg::Rect2i* destination)
{
  gpg::Rect2i* cursor = destination;
  for (const gpg::Rect2i* source = first; source != last; ++source, ++cursor) {
    *cursor = *source;
  }
  return cursor;
}

/**
 * Address: 0x00745020 (FUN_00745020, ?SerMapData@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Serializes map playable-rect state by writing:
 * - one `Rect2i` copied from `mMapData->mPlayableRect`;
 * - loaded map-rect vector count (`+0x0A08` lane);
 * - each loaded `Rect2i` element.
 */
void Sim::SerMapData(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  auto* const runtime = reinterpret_cast<SimSerMapDataRuntimeView*>(this);

  const gpg::Rect2i playableRect = runtime->mapData->mPlayableRect;
  gpg::RRef nullOwnerRef{};
  archive->Write(ResolveRect2iRType(), &playableRect, nullOwnerRef);

  std::uint32_t rectCount = 0;
  if (runtime->loadedMapRects.first != nullptr) {
    rectCount = static_cast<std::uint32_t>(runtime->loadedMapRects.last - runtime->loadedMapRects.first);
  }
  WriteArchiveUIntCompat(archive, rectCount);

  for (std::uint32_t index = 0; index < rectCount; ++index) {
    gpg::Rect2i* const loadedRects = runtime->loadedMapRects.first;
    if (loadedRects == nullptr) {
      break;
    }

    gpg::RRef elementOwnerRef{};
    archive->Write(ResolveRect2iRType(), &loadedRects[index], elementOwnerRef);
  }
}

/**
 * Address: 0x00745120 (FUN_00745120, ?SerMapData@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Deserializes one playable rectangle lane, applies it to `mMapData`, then
 * loads and mirrors the archive `Rect2i` cache vectors used by Sim map lanes.
 */
void Sim::SerMapData(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  auto* const runtime = reinterpret_cast<SimSerMapDataRuntimeView*>(this);

  gpg::Rect2i playableRect{};
  gpg::RRef ownerRef{};
  archive->Read(ResolveRect2iRType(), &playableRect, ownerRef);
  (void)runtime->mapData->SetPlayableMapRect(playableRect);

  std::uint32_t rectCount = 0;
  archive->ReadUInt(&rectCount);

  const gpg::Rect2i zeroRect{};
  Rect2VectorResizeDefault(rectCount, &runtime->loadedMapRects, &zeroRect, 0, 0, 0);
  for (std::uint32_t index = 0; index < rectCount; ++index) {
    gpg::RRef elementOwnerRef{};
    archive->Read(ResolveRect2iRType(), &runtime->loadedMapRects.first[index], elementOwnerRef);
  }

  if (runtime->loadedMapRects.first != nullptr) {
    const std::ptrdiff_t loadedCount = runtime->loadedMapRects.last - runtime->loadedMapRects.first;
    if (loadedCount > 0) {
      Rect2VectorResizeDefault(
        static_cast<std::uint32_t>(loadedCount),
        &runtime->cachedMapRects,
        &zeroRect,
        0,
        0,
        0
      );
      (void)Rect2CopyRange(runtime->loadedMapRects.first, runtime->loadedMapRects.last, runtime->cachedMapRects.first);
    }
  }
}

/**
 * Address: 0x007452B0 (FUN_007452B0, ?SerArmies@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Serializes owned army pointers from `mArmiesList` as count + owned
 * `SimArmy` raw-pointer entries.
 */
void Sim::SerArmies(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const std::uint32_t armyCount = static_cast<std::uint32_t>(mArmiesList.size());
  WriteArchiveUIntCompat(archive, armyCount);

  gpg::RRef ownerRef{};
  for (CArmyImpl* const army : mArmiesList) {
    gpg::RRef armyRef{};
    gpg::RRef_SimArmy(&armyRef, army);
    gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Owned, ownerRef);
  }
}

/**
 * Address: 0x00745330 (FUN_00745330, ?SerArmies@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads owned army pointers from archive into `mArmiesList` using
 * archive-count resize + per-entry owned pointer load.
 */
void Sim::SerArmies(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  unsigned int armyCount = 0u;
  archive->ReadUInt(&armyCount);

  mArmiesList.resize(static_cast<std::size_t>(armyCount));

  gpg::RRef nullOwner{};
  for (std::size_t i = 0; i < static_cast<std::size_t>(armyCount); ++i) {
    SimArmy* loadedArmy = nullptr;
    archive->ReadPointerOwned_SimArmy(&loadedArmy, &nullOwner);
    mArmiesList[i] = static_cast<CArmyImpl*>(loadedArmy);
  }
}

/**
 * Address: 0x007456D0 (FUN_007456D0, ?SerDirtyEnts@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Writes one unowned entity-pointer chain from `mCoordEntities` and
 * terminates the stream with a null entity sentinel.
 */
void Sim::SerDirtyEnts(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef nullOwner{};
  for (Entity* const entity : mCoordEntities.owners_member<Entity, &Entity::mCoordNode>()) {
    gpg::RRef entityRef{};
    gpg::RRef_Entity(&entityRef, entity);
    gpg::WriteRawPointer(archive, entityRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  gpg::RRef tailRef{};
  gpg::RRef_Entity(&tailRef, nullptr);
  gpg::WriteRawPointer(archive, tailRef, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x00745760 (FUN_00745760, ?SerDirtyEnts@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads one unowned entity-pointer stream and relinks each loaded entity's
 * coord-node into `mCoordEntities` until a null sentinel is encountered.
 */
void Sim::SerDirtyEnts(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  gpg::RRef ownerRef{};
  Entity* entity = nullptr;
  (void)archive->ReadPointer_Entity(&entity, &ownerRef);
  while (entity != nullptr) {
    entity->mCoordNode.ListLinkAfter(&mCoordEntities);
    ownerRef = gpg::RRef{};
    (void)archive->ReadPointer_Entity(&entity, &ownerRef);
  }
}

namespace
{
  /**
   * Address: 0x00744E50 (FUN_00744E50, sub_744E50)
   *
   * IDA signature:
   * void __usercall sub_744E50(gpg::ReadArchive* archive@<esi>, LuaPlus::LuaObject table);
   *
   * What it does:
   * Reads (key, value) LuaObject pairs from `archive` and assigns each into
   * `table` until a nil-key sentinel is read. Used to restore the sim's Lua
   * globals table at the end of the load-serialization pass. `table` is taken by
   * value (an owned copy destroyed on return), matching the binary.
   */
  void ReadLuaTableEntriesFromArchive(gpg::ReadArchive* const archive, LuaPlus::LuaObject table)
  {
    gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
    if (!luaObjectType) {
      luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = luaObjectType;
    }

    while (true) {
      LuaPlus::LuaObject key;
      gpg::RRef keyRef{};
      archive->Read(luaObjectType, &key, keyRef);
      if (key.IsNil()) {
        break;
      }

      LuaPlus::LuaObject value;
      gpg::RRef valueRef{};
      archive->Read(luaObjectType, &value, valueRef);
      table.SetObject(key, value);
    }
  }
} // namespace

/**
  * Alias of FUN_00754C60 (non-canonical helper lane).
 *
 * What it does:
 * Core Sim load-serialization routine used by Sim serializer callback.
 */
void Sim::SerializeLoadBody(gpg::ReadArchive* archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef = MakeSimOwnerRef(this);

  // 0x00754C60 order recovered from IDA/decomp.
  SerMapData(archive);
  archive->ReadUInt(&mCurTick);

  mRngState =
    static_cast<CRandomStream*>(LoadPointerByRType(archive, {"CRandomStream", "Moho::CRandomStream"}, ownerRef));
  mPhysConstants =
    static_cast<SPhysConstants*>(LoadPointerByRType(archive, {"SPhysConstants", "Moho::SPhysConstants"}, ownerRef));
  mOGrid = static_cast<COGrid*>(LoadPointerByRType(archive, {"COGrid", "Moho::COGrid"}, ownerRef));
  mFormationDB =
    static_cast<CAiFormationDBImpl*>(LoadPointerByRType(archive, {"IAiFormationDB", "Moho::IAiFormationDB"}, ownerRef));
  mEntityDB =
    static_cast<CEntityDb*>(LoadPointerByRType(archive, {"EntityDB", "CEntityDB", "Moho::EntityDB"}, ownerRef));
  archive->ReadUInt(&mReserved98C);
  mDecalBuffer =
    static_cast<CDecalBuffer*>(LoadPointerByRType(archive, {"CDecalBuffer", "Moho::CDecalBuffer"}, ownerRef));
  mEffectManager =
    static_cast<CEffectManagerImpl*>(LoadPointerByRType(archive, {"IEffectManager", "Moho::IEffectManager"}, ownerRef));
  mSoundManager =
    static_cast<CSimSoundManager*>(LoadPointerByRType(archive, {"ISoundManager", "Moho::ISoundManager"}, ownerRef));

  LoadTaskStages(archive, &mTaskStageA, &mDiskWatcherTaskStage, &mTaskStageB, ownerRef);
  SerVars(archive);
  LoadObjectByRType(archive, &mShields, {"std::list<Moho::Shield *>", "list<Moho::Shield *>"}, ownerRef);
  SerDirtyEnts(archive);

  bool bitFlag = false;
  archive->ReadBool(&bitFlag);
  mCheatsEnabled = bitFlag;
  archive->ReadBool(&bitFlag);
  mGameOver = bitFlag;

  mCommandDB =
    static_cast<CCommandDb*>(LoadPointerByRType(archive, {"CCommandDB", "CCommandDb", "Moho::CCommandDB"}, ownerRef));

  // Restore the sim's Lua globals table: read (key, value) pairs into the globals
  // until a nil-key sentinel (binary tail: mLuaState->GetGlobals() + FUN_00744E50).
  LuaPlus::LuaObject globals = mLuaState->GetGlobals();
  ReadLuaTableEntriesFromArchive(archive, globals);
}

/**
 * Address: 0x00745390 (FUN_00745390, ?SerVars@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Writes active sim-console variables as `(name, lexical value)` string pairs
 * and terminates the lane with an empty string name sentinel.
 */
void Sim::SerVars(gpg::WriteArchive* archive)
{
  if (!archive) {
    return;
  }

  const std::size_t simVarCount = mSimVars.size();
  for (std::size_t i = 0; i < simVarCount; ++i) {
    CSimConVarInstanceBase* const simVar = mSimVars[i];
    if (!simVar) {
      continue;
    }

    msvc8::string varName(simVar->mName ? simVar->mName : "");
    archive->WriteString(&varName);

    gpg::RRef valueRef{};
    simVar->GetValueRef(&valueRef);
    msvc8::string lexical = valueRef.GetLexical();
    archive->WriteString(&lexical);
  }

  msvc8::string endOfVars;
  archive->WriteString(&endOfVars);
}

/**
 * Address: 0x00745500 (FUN_00745500, ?SerVars@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 * Mangled: ?SerVars@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z
 *
 * IDA signature:
 * void __stdcall Moho::Sim::SerVars(Moho::Sim *this, gpg::ReadArchive &archive, int);
 *
 * What it does:
 * Load counterpart of SerVars(WriteArchive*): restores console-variable
 * overrides. Reads a var name; while non-empty, reads its lexical value,
 * looks the name up in the `simcons` sim-command registry, and (when found)
 * resolves/creates the per-Sim CSimConVarInstanceBase indexed by
 * CSimConVarBase::mIndex, growing `mSimVars` to the global convar-index
 * counter, then applies the value through the instance's reflection RRef via
 * SetLexical. Unknown names are logged.
 */
void Sim::SerVars(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  msvc8::string varName;
  archive->ReadString(&varName);
  while (!varName.empty()) {
    msvc8::string varValue;
    archive->ReadString(&varValue);

    // `simcons` map value is a CSimConVarBase (only convar entries are saved by
    // SerVars(WriteArchive*)); the binary's virtual Identity() adjustment is a
    // no-op for this single-inheritance chain, so a static_cast is 1:1.
    CSimConVarBase* const conVar = static_cast<CSimConVarBase*>(FindRegisteredSimConCommand(varName.c_str()));
    if (!conVar) {
      Logf("Reference to unknown console variable: %s", varName.c_str());
    } else {
      const std::size_t index = static_cast<std::size_t>(conVar->mIndex);
      if (mSimVars.size() <= index) {
        // Binary reserves to the global convar count in one shot (not index+1).
        mSimVars.resize(static_cast<std::size_t>(GetSimConVarIndexCounter()), nullptr);
      }

      CSimConVarInstanceBase* instance = mSimVars[index];
      if (!instance) {
        instance = conVar->CreateInstance();
        mSimVars[index] = instance;
      }

      gpg::RRef valueRef{};
      instance->GetValueRef(&valueRef);
      valueRef.SetLexical(varValue.c_str());
    }

    archive->ReadString(&varName);
  }
}

/**
 * Address: 0x007551C0 (FUN_007551C0, ?Dump@CMauiControl@Moho@@UAEXXZ_0)
 *
 * What it does:
 * Core Sim save-serialization routine used by Sim serializer callback.
 */
void Sim::SerializeSaveBody(gpg::WriteArchive* archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef = MakeSimOwnerRef(this);

  // 0x007551C0 order recovered from IDA/decomp.
  SerMapData(archive);
  WriteArchiveUIntCompat(archive, mCurTick);

  SavePointerByRType(
    archive, mRngState, {"CRandomStream", "Moho::CRandomStream"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mPhysConstants, {"SPhysConstants", "Moho::SPhysConstants"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(archive, mOGrid, {"COGrid", "Moho::COGrid"}, gpg::TrackedPointerState::Owned, ownerRef);
  SavePointerByRType(
    archive, mFormationDB, {"IAiFormationDB", "Moho::IAiFormationDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mEntityDB, {"EntityDB", "CEntityDB", "Moho::EntityDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SerArmies(archive);
  WriteArchiveUIntCompat(archive, mReserved98C);
  SavePointerByRType(
    archive, mDecalBuffer, {"CDecalBuffer", "Moho::CDecalBuffer"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mEffectManager, {"IEffectManager", "Moho::IEffectManager"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mSoundManager, {"ISoundManager", "Moho::ISoundManager"}, gpg::TrackedPointerState::Owned, ownerRef
  );

  SaveTaskStages(archive, &mTaskStageA, &mDiskWatcherTaskStage, &mTaskStageB, ownerRef);
  SerVars(archive);
  SaveObjectByRType(archive, &mShields, {"std::list<Moho::Shield *>", "list<Moho::Shield *>"}, ownerRef);
  SerDirtyEnts(archive);

  archive->WriteBool(mCheatsEnabled);
  archive->WriteBool(mGameOver);
  SavePointerByRType(
    archive, mCommandDB, {"CCommandDB", "CCommandDb", "Moho::CCommandDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );

  // Persist the sim's Lua globals table as (key, value) entries + nil terminator
  // (binary tail: mLuaState->GetGlobals() + func_ArchiveWriteLuaObj).
  LuaPlus::LuaObject globals = mLuaState->GetGlobals();
  (void)func_ArchiveWriteLuaObj(archive, &globals);
}

/**
 * Address: 0x00744F70 (FUN_00744F70, sub_744F70)
 *
 * IDA signature:
 * int __cdecl sub_744F70(int a1, int a2)
 *
 * What it does:
 * Ser-load callback thunk: forwards archive/object args to 0x00754C60.
 * Extra serializer callback args are ignored in retail.
 */
void moho::SimSerializerLoadThunk(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
{
  if (objectPtr == 0) {
    return;
  }

  reinterpret_cast<Sim*>(objectPtr)->SerializeLoadBody(archive);
}

/**
 * Address: 0x00744F80 (FUN_00744F80, sub_744F80)
 *
 * IDA signature:
 * void __cdecl sub_744F80(Moho::CMauiControl *a1)
 *
 * What it does:
 * Ser-save callback thunk: forwards archive/object args to 0x007551C0.
 * Extra serializer callback args are ignored in retail.
 */
void moho::SimSerializerSaveThunk(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
{
  if (objectPtr == 0) {
    return;
  }

  reinterpret_cast<Sim*>(objectPtr)->SerializeSaveBody(archive);
}

/**
 * Address: 0x00747460 (FUN_00747460, ?GetSimVar@Sim@Moho@@QAEPAVCSimConVarInstanceBase@2@PAVCSimConVarBase@2@@Z)
 *
 * Moho::CSimConVarBase *
 *
 * IDA signature:
 * Moho::CSimConVarInstanceBase *__usercall Moho::Sim::GetSimVar@<eax>(Moho::Sim *this@<edi>, Moho::CSimConVarBase
 * *var@<ebx>);
 *
 * What it does:
 * Returns the cached Sim convar instance for `var->mIndex`, creating it on first access.
 */
CSimConVarInstanceBase* Sim::GetSimVar(CSimConVarBase* var)
{
  if (!var) {
    return nullptr;
  }

  const std::size_t index = static_cast<std::size_t>(var->mIndex);
  if (mSimVars.size() <= index) {
    mSimVars.resize(index + 1u, nullptr);
  }

  CSimConVarInstanceBase* instance = mSimVars[index];
  if (instance) {
    return instance;
  }

  instance = var->CreateInstance();
  mSimVars[index] = instance;
  return instance;
}

namespace
{
  struct SyncReserveCountsRuntimeView
  {
    std::int32_t mAudioRequests = 0; // +0x00
    std::int32_t mArmyData = 0; // +0x04
    std::int32_t mEntityData = 0; // +0x08
    std::int32_t mUnitData = 0; // +0x0C
    std::int32_t mCommandData = 0; // +0x10
  };
  static_assert(sizeof(SyncReserveCountsRuntimeView) == 0x14, "SyncReserveCountsRuntimeView size must be 0x14");

  struct LegacyFastVectorRuntimeSlot
  {
    std::uint32_t mProxyWord = 0; // +0x00
    std::uint8_t* mFirst = nullptr; // +0x04
    std::uint8_t* mLast = nullptr; // +0x08
    std::uint8_t* mEnd = nullptr; // +0x0C
  };
  static_assert(sizeof(LegacyFastVectorRuntimeSlot) == 0x10, "LegacyFastVectorRuntimeSlot size must be 0x10");
  static_assert(
    offsetof(LegacyFastVectorRuntimeSlot, mFirst) == 0x04,
    "LegacyFastVectorRuntimeSlot::mFirst offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyFastVectorRuntimeSlot, mLast) == 0x08,
    "LegacyFastVectorRuntimeSlot::mLast offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyFastVectorRuntimeSlot, mEnd) == 0x0C,
    "LegacyFastVectorRuntimeSlot::mEnd offset must be 0x0C"
  );

  struct SSyncDataReserveLaneRuntimeView
  {
    std::uint8_t pad_0000_0014[0x14]{}; // +0x000
    LegacyFastVectorRuntimeSlot mAudioRequests; // +0x014
    std::uint8_t pad_0024_0118[0xF4]{}; // +0x024
    LegacyFastVectorRuntimeSlot mArmyUpdates; // +0x118
    std::uint8_t pad_0128_0148[0x20]{}; // +0x128
    LegacyFastVectorRuntimeSlot mEntityUpdates; // +0x148
    LegacyFastVectorRuntimeSlot mUnitUpdates; // +0x158
    std::uint8_t pad_0168_0198[0x30]{}; // +0x168
    LegacyFastVectorRuntimeSlot mCommandUpdates; // +0x198
  };
  static_assert(
    offsetof(SSyncDataReserveLaneRuntimeView, mAudioRequests) == 0x14,
    "SSyncDataReserveLaneRuntimeView::mAudioRequests offset must be 0x14"
  );
  static_assert(
    offsetof(SSyncDataReserveLaneRuntimeView, mArmyUpdates) == 0x118,
    "SSyncDataReserveLaneRuntimeView::mArmyUpdates offset must be 0x118"
  );
  static_assert(
    offsetof(SSyncDataReserveLaneRuntimeView, mEntityUpdates) == 0x148,
    "SSyncDataReserveLaneRuntimeView::mEntityUpdates offset must be 0x148"
  );
  static_assert(
    offsetof(SSyncDataReserveLaneRuntimeView, mUnitUpdates) == 0x158,
    "SSyncDataReserveLaneRuntimeView::mUnitUpdates offset must be 0x158"
  );
  static_assert(
    offsetof(SSyncDataReserveLaneRuntimeView, mCommandUpdates) == 0x198,
    "SSyncDataReserveLaneRuntimeView::mCommandUpdates offset must be 0x198"
  );

  [[nodiscard]] std::int32_t CountFastVectorLaneElements(
    const LegacyFastVectorRuntimeSlot& lane,
    const std::size_t elementStride
  ) noexcept
  {
    if (lane.mFirst == nullptr || lane.mLast == nullptr || lane.mLast < lane.mFirst || elementStride == 0u) {
      return 0;
    }

    const std::size_t bytes = static_cast<std::size_t>(lane.mLast - lane.mFirst);
    return static_cast<std::int32_t>(bytes / elementStride);
  }

  /**
   * Address: 0x00560940 (FUN_00560940)
   *
   * What it does:
   * Calculates five sync payload reservation counts from the previous packet's
   * fastvector lanes and writes them into Sim's reserve cache.
   */
  void SnapshotSyncReserveCounts(
    const SSyncData& data,
    SyncReserveCountsRuntimeView& outCounts
  ) noexcept
  {
    const auto& lanes = reinterpret_cast<const SSyncDataReserveLaneRuntimeView&>(data);
    outCounts.mAudioRequests = CountFastVectorLaneElements(lanes.mAudioRequests, 0x1Cu);
    outCounts.mArmyData = CountFastVectorLaneElements(lanes.mArmyUpdates, 0x160u);
    outCounts.mEntityData = CountFastVectorLaneElements(lanes.mEntityUpdates, 0xD8u);
    outCounts.mUnitData = CountFastVectorLaneElements(lanes.mUnitUpdates, 0x238u);
    outCounts.mCommandData = CountFastVectorLaneElements(lanes.mCommandUpdates, 0x78u);
  }

  /**
   * Address: 0x00560A00 (FUN_00560A00, Moho::SSyncData::ReserveSizes)
   *
   * IDA signature:
   * void __stdcall Moho::SSyncData::ReserveSizes(struct_SyncSizes *a1, Moho::SSyncData *a2);
   *
   * What it does:
   * Pre-reserves every per-beat sync vector to the element counts
   * `SnapshotSyncReserveCounts` captured from the previous packet, so the
   * fill loops later in `Sim::Sync` do not pay for a grow-reallocation on
   * the common case where this beat's counts match the last one's.
   *
   * Field mapping confirmed from `SSyncDataReserveLaneRuntimeView`'s offsets
   * (cited on `SnapshotSyncReserveCounts` above): the binary's
   * `mCommandUpdates` lane is `SSyncData::mPublishedCommandPackets` (+0x198,
   * element stride 0x78) -- there is no field literally named
   * `mCommandUpdates` in the recovered layout, the two names refer to the
   * same +0x198 vector.
   *
   * `mAudioRequests` reserves through `gpg::core::FastVectorN::Reserve`
   * (0x00561460, already recovered as the shared inline-capacity grow
   * lane); the other four reserve through `msvc8::vector<T>::reserve`
   * (legacy/containers/Vector.h) -- `mArmyUpdates` via FUN_00560D60,
   * `mEntityUpdates` via FUN_00560EB0 (both cited there), `mUnitUpdates`
   * via FUN_00561000, and `mPublishedCommandPackets` via FUN_00561160
   * (verified: the 0x78-byte `SSyncPublishedCommandPacket` element's
   * `reserve()` grow chain -- max_size guard FUN_00561900, allocator
   * FUN_00562850, uninit-copy FUN_005634F0 -- all cited on their
   * respective `Vector.h` template members).
   */
  void ReserveSyncDataSizes(const SyncReserveCountsRuntimeView& sizes, SSyncData& syncData) noexcept
  {
    syncData.mAudioRequests.Reserve(static_cast<std::size_t>(sizes.mAudioRequests));
    syncData.mArmyUpdates.reserve(static_cast<std::size_t>(sizes.mArmyData));
    syncData.mEntityUpdates.reserve(static_cast<std::size_t>(sizes.mEntityData));
    syncData.mUnitUpdates.reserve(static_cast<std::size_t>(sizes.mUnitData));
    syncData.mPublishedCommandPackets.reserve(static_cast<std::size_t>(sizes.mCommandData));
  }

  void AppendLegacyStringToStd(std::string& out, const msvc8::string& value)
  {
    out.append(value.c_str(), value.size());
  }

  /**
   * Address: 0x00747954..0x007479C8 (inside FUN_007474B0, Moho::Sim::Sync)
   *
   * What it does:
   * Publishes how many entities the beat's sync walk visited. The stat handle
   * is looked up once and cached in a file static, released to zero on first
   * acquisition, and the count is then stored through `StatItem::SetInt` -
   * which is the interlocked compare-exchange loop on `mPrimaryValueBits`
   * (+0x24) the binary open-codes here.
   */
  void StoreSyncEntityCountStat(const std::int32_t syncedEntityCount)
  {
    static moho::StatItem* sEngineStatSyncEntityCount = nullptr;
    if (sEngineStatSyncEntityCount == nullptr) {
      if (moho::EngineStats* const stats = moho::GetEngineStats(); stats != nullptr) {
        sEngineStatSyncEntityCount = stats->GetItem2("Sync_Entity_Count");
        if (sEngineStatSyncEntityCount != nullptr) {
          (void)sEngineStatSyncEntityCount->Release(0);
        }
      }
    }

    if (sEngineStatSyncEntityCount != nullptr) {
      (void)sEngineStatSyncEntityCount->SetInt(&syncedEntityCount);
    }
  }
} // namespace

/**
 * Address: 0x007474B0 (FUN_007474B0)
 *
 * What it does:
 * Produces one sync packet from current Sim state and requested filter values.
 *
 * Recovery status:
 * Partial lift. Keeps filter-transfer behavior and minimal beat packet publication
 * so CSimDriver queue/event flow stays consistent while full body recovery is pending.
 */
void Sim::Sync(const SSyncFilter& filter, SSyncData*& outSyncData)
{
  // 0x007474EC..0x00747506: the focus army is compared BEFORE the incoming
  // filter is adopted - `a3a[0] = mFocusArmy != v4` reads the old value off
  // `mSyncfilter` and the new one off the argument, then `SSyncFilter::
  // SSyncFilter(&this->mSyncfilter, that)` overwrites it. Copying first would
  // make the two always equal and the flag permanently false.
  const std::int32_t previousFocusArmy = mSyncFilter.focusArmy;
  mSyncFilter.CopyFrom(filter);
  const bool focusArmyChanged = previousFocusArmy != filter.focusArmy;

  if (focusArmyChanged && mLuaState != nullptr) {
    // 0x00747512..0x00747560: Lua is told about the switch with 1-based army
    // indices, except that "no focus army" stays -1 rather than becoming 0.
    const auto toLuaArmyIndex = [](const std::int32_t index) {
      return index == -1 ? -1 : index + 1;
    };
    // Argument order is (new, old): ground truth computes `v6` from the
    // incoming filter and `v5` from the old value and calls `Call_Int2(v6, v5)`,
    // matching `function NoteFocusArmyChanged(new, old)` in lua/SimSync.lua.
    const LuaPlus::LuaObject noteFocusArmyChangedGlobal = mLuaState->GetGlobal("NoteFocusArmyChanged");
    if (noteFocusArmyChangedGlobal.IsFunction()) {
      const LuaPlus::LuaFunction<> noteFocusArmyChanged(noteFocusArmyChangedGlobal);
      noteFocusArmyChanged.Call_Int2(toLuaArmyIndex(filter.focusArmy), toLuaArmyIndex(previousFocusArmy));
    }
  }

  delete outSyncData;
  outSyncData = new SSyncData{};
  // The four scalars the client reads its clocks off. Without `mCurTick` the
  // session's `mGameTick` never moves, which is what froze the game clock.
  outSyncData->mCurBeat = static_cast<int32_t>(mCurBeat);
  outSyncData->mCurTick = static_cast<int32_t>(mCurTick);
  outSyncData->mAdvanced = mAdvancedThisTick;
  outSyncData->mFocusArmy = mSyncFilter.focusArmy;

  // 0x00747635..0x0074764C: hand the beat's queued audio requests to the
  // packet and reset the sim-side queue back to its inline storage. Without
  // this the packet's audio lane stayed empty for every beat, so nothing the
  // sim played ever reached `CUserSoundManager::UpdateSoundRequests`.
  if (mSoundManager != nullptr) {
    mSoundManager->DrainRequests(outSyncData->mAudioRequests);
  }

  SnapshotSyncReserveCounts(
    *outSyncData,
    *reinterpret_cast<SyncReserveCountsRuntimeView*>(mSyncReserveCounts)
  );
  ReserveSyncDataSizes(*reinterpret_cast<SyncReserveCountsRuntimeView*>(mSyncReserveCounts), *outSyncData);

  // 0x00747A54: the army roster is published exactly once, on the first sync.
  // `CWldSession::DoBeat` turns each entry into a `UserArmy` and files it by
  // army index, so until this runs the client's army run stays all-null and
  // anything reading it - `GetArmiesTable`, `IsObserver`, the score and
  // diplomacy panels - has nothing to read.
  if (!mDidSync) {
    const std::size_t armyCount = mArmiesList.size();
    outSyncData->mNewGrids.resize(armyCount);
    for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
      (void)mArmiesList[armyIndex]->CopyArmyConstantData(&outSyncData->mNewGrids[armyIndex]);
    }
    mDidSync = true;
  }

  // 0x00747AE9: the variable half goes out every beat, positionally - the Nth
  // record belongs to the Nth army, which is how `DoBeat` reads it back.
  {
    const std::size_t armyCount = mArmiesList.size();
    outSyncData->mArmyUpdates.resize(armyCount);
    for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
      (void)mArmiesList[armyIndex]->CopyArmyVariableData(&outSyncData->mArmyUpdates[armyIndex]);
    }
  }

  // 0x007478A4..0x00747952: publish every entity that needs it into the packet.
  // This is what turns sim entities into client-side ones at all: `Entity::Sync`
  // calls `CreateInterface` the first time it sees an entity whose interface is
  // not yet created, and that is the only producer of `mNewEntities` /
  // `mNewUnits`. Without this walk the packet's entity lanes are empty forever,
  // so `CWldSession::DoBeat` never constructs a `UserEntity`/`UserUnit`,
  // `UserArmy::mAvatars` stays empty, and `GetArmyAvatars` returns nothing.
  //
  // Two lanes, selected by whether the focus army just changed:
  //   changed -> every unit in the DB is resynced, because visibility is
  //              computed against the focus army and all of it just became
  //              stale (0x007478C2 walks `mEntityDB->mAllUnits`);
  //   otherwise -> only the dirty run threaded through `Entity::mCoordNode`
  //              (0x0074791E walks `mCoordEntities`).
  //
  // Both dispatch the same virtual, vtable slot 12 (`mov eax, [edx+30h]`), and
  // both count into `Sync_Entity_Count`. The incremental walk advances to the
  // successor BEFORE dispatching (`mov esi, [esi+4]` precedes the call),
  // because `Entity::Sync` unlinks the node it was reached through.
  std::int32_t syncedEntityCount = 0;
  if (focusArmyChanged) {
    ForEachAllArmyUnit(mEntityDB, [&](Unit* const unit) {
      unit->Sync(outSyncData);
      ++syncedEntityCount;
    });
  } else {
    auto dirtyEntities = mCoordEntities.owners_member<Entity, &Entity::mCoordNode>();
    for (auto it = dirtyEntities.begin(); it != dirtyEntities.end();) {
      Entity* const entity = *it;
      ++it;
      if (entity != nullptr) {
        entity->Sync(outSyncData);
        ++syncedEntityCount;
      }
    }
  }
  StoreSyncEntityCountStat(syncedEntityCount);

  if (mRequestXMLArmyStatsSubmit) {
    mRequestXMLArmyStatsSubmit = false;

    std::string armyStatsXml;
    armyStatsXml.append("<?xml version=\"1.0\" ?>\n");
    armyStatsXml.append(
      "<GameStats xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"
    );

    const msvc8::string armyIndent("  ");
    for (auto it = mArmiesList.begin(); it != mArmiesList.end(); ++it) {
      CArmyImpl* const army = *it;
      CArmyStats* const armyStats = army->GetArmyStats();
      AppendLegacyStringToStd(armyStatsXml, armyStats->ArmyXmlStatsNode(armyIndent));
    }
    armyStatsXml.append("</GameStats>\n");

    outSyncData->mSubmitArmyStats.assign_owned(std::string_view(armyStatsXml.data(), armyStatsXml.size()));
  }

  // 0x00747AF2..0x00747B0C: drain the entity DB's pending-destroy queue, then
  // publish the command DB's per-beat events. Ground truth runs these back to
  // back with `forceRefresh` = the same focus-army-changed byte that selected
  // the entity walk above:
  //
  //     mov  eax, [ebx+984h]   ; mEntityDB
  //     call EntityDB::Purge
  //     mov  ecx, [edi]        ; syncData
  //     mov  edx, [ebp+a3]     ; forceRefresh
  //     mov  eax, [ebx+988h]   ; mCommandDb  (NOT +0x984 - adjacent to it)
  //     call CCommandDb::PublishSyncData
  //
  // `EntityDB::Purge` (0x00684560) has exactly one caller in the binary and
  // this is it, so nothing destroyed the queued entities before this; and
  // `PublishSyncData` had no source-level caller at all, so per-command sync
  // events never reached the client.
  if (mEntityDB != nullptr) {
    mEntityDB->Purge();
  }
  if (mCommandDB != nullptr) {
    mCommandDB->PublishSyncData(outSyncData, focusArmyChanged);
  }

  // 0x00747B23 onward: republish the per-beat state Lua reads off the global
  // `Sync` table. lua/SimSync.lua consumes these every beat; nothing wrote
  // them, so the table's pause and cheater lanes were permanently stale.
  //
  //     LuaState::GetGlobal(mLuaState, &syncTable, "Sync");
  //     if (mPausedBy == -1) { SetNil("PausedBy"); SetNil("TimeoutsRemaining"); }
  //     else { SetInteger("PausedBy", mPausedBy + 1);
  //            SetInteger("TimeoutsRemaining",
  //                       mCommandSources[mPausedBy].mTimeouts); }
  //     ... if (mCheaters non-empty) { t[i+1] = mCheaters[i] + 1;
  //                                    SetObject("Cheaters", t);
  //                                    mCheaters._Mylast = _Myfirst; }
  //
  // Both index lanes are published 1-based, matching every other army/source
  // index handed to Lua; the cheater run is cleared after publication so each
  // entry is reported exactly once.
  if (mLuaState != nullptr) {
    LuaPlus::LuaObject syncTable = mLuaState->GetGlobal("Sync");
    if (syncTable.IsTable()) {
      const std::int32_t pausedBy = mPausedByCommandSource;
      if (pausedBy == -1) {
        syncTable.SetNil("PausedBy");
        syncTable.SetNil("TimeoutsRemaining");
      } else {
        syncTable.SetInteger("PausedBy", pausedBy + 1);
        if (static_cast<std::size_t>(pausedBy) < mCommandSources.size()) {
          syncTable.SetInteger("TimeoutsRemaining", mCommandSources[static_cast<std::size_t>(pausedBy)].mTimeouts);
        }
      }

      // 0x00747B8x..: the focused army's stat tree goes out as `__ArmyStats`
      // with the current tick stamped on it. Ground truth reads the root item
      // as `*(StatItem **)(v68 + 4)` off the CArmyStats - that is
      // `Stats<CArmyStatItem>::mItem` (+0x04, asserted in Stats.h), and
      // CArmyStatItem derives from StatItem, so the read is a plain upcast.
      if (mSyncArmy > -1 && static_cast<std::size_t>(mSyncArmy) < mArmiesList.size()) {
        if (CArmyImpl* const syncArmy = mArmiesList[static_cast<std::size_t>(mSyncArmy)]; syncArmy != nullptr) {
          if (CArmyStats* const armyStats = syncArmy->GetArmyStats(); armyStats != nullptr) {
            LuaPlus::LuaObject armyStatsTable{};
            STAT_GetLuaTable(mLuaState, armyStats->mItem, armyStatsTable);
            armyStatsTable.SetInteger("Tick", static_cast<std::int32_t>(mCurTick));
            syncTable.SetObject("__ArmyStats", armyStatsTable);
          }
        }
      }

      if (!mCheaters.empty()) {
        LuaPlus::LuaObject cheaters(mLuaState);
        cheaters.AssignNewTable(mLuaState, 0, 0u);
        std::int32_t luaIndex = 1;
        for (auto it = mCheaters.begin(); it != mCheaters.end(); ++it, ++luaIndex) {
          cheaters.SetInteger(luaIndex, *it + 1);
        }
        // The flag rides on the same table as the cheater run, not on `Sync`.
        cheaters.SetBoolean("CheatsEnabled", mCheatsEnabled);
        syncTable.SetObject("Cheaters", cheaters);
        mCheaters.clear();
      }
    }

    // 0x00747BF1..0x00747C3x: flatten the table just written into the beat's
    // packet. This is the sim -> UI data channel - everything set on `Sync`
    // above only reaches the client because it is serialised here, so a beat
    // that skips this step publishes an empty payload no matter what the
    // table holds.
    //
    //     v79 = new MemBufferStream(256);
    //     if (v79 != dataPtr->mStream && dataPtr->mStream)
    //         dataPtr->mStream->dtr_Stream(dataPtr->mStream, 1);
    //     dataPtr->mStream = v79;
    //     SCR_ToByteStream(&syncTable, dataPtr->mStream);
    //
    // The serialisation runs on the same object the setters above wrote, and
    // is not guarded by the table check: a non-table `Sync` still emits its
    // tagged payload. The previous stream is released only when it is not the
    // one being installed; the packet is freshly built each beat so it is
    // normally null, but that is the shape the binary has.
    auto* const beatStream = new gpg::MemBufferStream(256u);
    if (beatStream != outSyncData->mStream && outSyncData->mStream != nullptr) {
      delete outSyncData->mStream;
    }
    outSyncData->mStream = beatStream;

    (void)syncTable.ToByteStream(*outSyncData->mStream);
  }

  // The desync run is moved, not copied: the sim hands its accumulated
  // reports to the packet and takes the packet's (empty) run in exchange, so
  // each report is published exactly once.
  if (!mDesyncs.empty()) {
    mDesyncs.swap(outSyncData->mDesyncs);
  }

  // 0x0074820x onward: the remaining per-beat packet fields. `CWldSession::
  // DoBeat` reads every one of these each beat -- `mPausedBy` into
  // `mSessionPauseStateA`, `mFogOfWar` into `ren_FogOfWar`, `mSimResources`
  // through `ReseatSharedLane` -- but nothing here wrote them, so they were
  // pinned at their default-constructed values for the whole session.
  //
  //     (*dataPtr)->mPausedBy = this->mPausedBy;
  //     (*dataPtr)->mGameOver = this->mGameOver;
  //     if (mArmiesList non-empty)
  //         v88 = mArmiesList[0]->GetReconDB()->ReconGetFogOfWar();
  //     else v88 = 0;
  //     (*dataPtr)->mFogOfWar = v88;
  //     ... mTerrainUpdate ...
  //     (*dataPtr)->mSimResources = this->mSimResources;
  outSyncData->mPausedBy = mPausedByCommandSource;
  outSyncData->mGameOver = mGameOver;

  // Fog of war is read off the FIRST army only, not the focused one, and is
  // false when there are no armies at all. `GetReconDB` is the virtual at
  // vtable +0x20 that the binary dispatches through.
  bool fogOfWar = false;
  if (!mArmiesList.empty()) {
    if (CArmyImpl* const firstArmy = mArmiesList[0]; firstArmy != nullptr) {
      if (CAiReconDBImpl* const reconDb = firstArmy->GetReconDB(); reconDb != nullptr) {
        fogOfWar = reconDb->ReconGetFogOfWar();
      }
    }
  }
  outSyncData->mFogOfWar = fogOfWar;

  // The terrain the client renders. `sub_743180` in the decompile is the
  // shared_ptr copy the compiler materialises for the assignment's right-hand
  // side; the body after it is the inlined `operator=`. `DoBeat` feeds this
  // straight to `terrainRes->SyncTerrain(beat.mTerrainUpdate.px)`, so leaving
  // it unset handed the terrain renderer a null height field every beat.
  if (mMapData != nullptr) {
    outSyncData->mTerrainUpdate.reset_from_owner(mMapData->mHeightField);
  }

  // The decompiled body here is the inlined `shared_ptr::operator=` -- copy the
  // pointer, add a reference to the incoming control block, release the
  // outgoing one. `reset_from` is that mechanic on the wrapper itself.
  outSyncData->mSimResources.reset_from(mSimResources);

  // 0x00748311..0x00748336: the beat is published, so retire it. The
  // advanced-this-tick latch is consumed with it, and the game-over flag the
  // rules layer raised becomes the one the client is told about.
  mDidProcess = false;
  ++mCurBeat;
  FlushLog();
  mAdvancedThisTick = false;
  mGameOver = mGameEnded;
}

/**
 * Address: 0x00743370 (FUN_00743370, func_FormatBeatStr)
 *
 * What it does:
 * Builds one checksum-log file path as `<prefix>beat%05d.log`.
 */
[[nodiscard]] static msvc8::string FormatBeatLogFilePath(const msvc8::string& logFilePrefix, const int beat)
{
  return gpg::STR_Printf("%sbeat%05d.log", logFilePrefix.c_str(), beat);
}

/**
 * Address: 0x0074ADB0 (FUN_0074ADB0, ?FlushLog@Sim@Moho@@AAEXXZ)
 *
 * What it does:
 * Closes the active checksum log file, trims retained stale log files,
 * and opens the current beat log file.
 */
void Sim::FlushLog()
{
  if (!mLog) {
    return;
  }

  std::fclose(mLog);
  mLog = nullptr;

  if (!sim_KeepAllLogFiles && mIsDesyncFree) {
    mDesyncLogLines.push_back(mDesyncLogLine);
  }

  const int checksumPeriod = ReadSimConVarInt(this, ChecksumPeriodConVar(), 0);
  const int retainedLogCount = checksumPeriod + 20;
  while (static_cast<int>(mDesyncLogLines.size()) > retainedLogCount) {
    const msvc8::string staleLogPath = mDesyncLogLines.front();
    mDesyncLogLines.erase(mDesyncLogLines.begin());

    if (!DeleteFileA(staleLogPath.c_str())) {
      gpg::Warnf("Error deleting sim log file: %s", staleLogPath.c_str());
    }
  }

  mDesyncLogLine = FormatBeatLogFilePath(mLogFilePrefix, static_cast<int>(mCurBeat));
  if (fopen_s(&mLog, mDesyncLogLine.c_str(), "w") != 0) {
    mLog = nullptr;
  }
  mIsDesyncFree = true;
}

/**
 * Address: 0x005C3710 (FUN_005C3710, sub_5C3710)
 *
 * What it does:
 * Refreshes command/visibility blips for the active sim frame.
 */
void Sim::RefreshBlips()
{
  if (!mCommandDB || !mCommandDB->commands.header_ptr()) {
    return;
  }

  for (auto it = mCommandDB->commands.begin(); it != mCommandDB->commands.end(); ++it) {
    if (CUnitCommand* const command = it->second) {
      command->RefreshBlipState();
    }
  }
}

/**
 * Address: 0x0074A640 (FUN_0074A640, sub_74A640)
 *
 * What it does:
 * Rebuilds the per-beat simulation checksum digest.
 */
void Sim::UpdateChecksum()
{
  auto logChecksumDigest = [this]() {
    if (!mLog) {
      return;
    }

    const msvc8::string digestText = mContext.Digest().ToString();
    Logf("      %s\n", digestText.c_str());
  };

  const bool shouldUpdateReconChecksum = (mCurBeat % 100u) == 0u;

  Logf("Armies\n");
  for (auto it = mArmiesList.begin(); it != mArmiesList.end(); ++it) {
    CArmyImpl* const army = *it;
    Logf("  \"%s\" [%s]\n", army->ArmyName.raw_data_unsafe(), army->ArmyTypeText.raw_data_unsafe());

    const SEconTotals& economy = army->GetEconomy()->economy;
    mContext.Update(&economy, sizeof(economy));
    if (mLog) {
      Logf("    mStored=%.1f,%.1f\n", economy.mStored.ENERGY, economy.mStored.MASS);
      Logf("    mIncome=%.1f,%.1f\n", economy.mIncome.ENERGY, economy.mIncome.MASS);
      Logf("    mReclaimed=%.1f,%.1f\n", economy.mReclaimed.ENERGY, economy.mReclaimed.MASS);
      Logf("    mLastUseRequested=%.1f,%.1f\n", economy.mLastUseRequested.ENERGY, economy.mLastUseRequested.MASS);
      Logf("    mLastUseActual=%.1f,%.1f\n", economy.mLastUseActual.ENERGY, economy.mLastUseActual.MASS);
      const std::uint64_t energyStorageBits = economy.mMaxStorage.ENERGY;
      Logf(
        "    mMaxStorage.ENERGY=%I64\n",
        static_cast<std::uint32_t>(energyStorageBits & 0xFFFFFFFFu),
        static_cast<std::uint32_t>(energyStorageBits >> 32)
      );
      const std::uint64_t massStorageBits = economy.mMaxStorage.MASS;
      Logf(
        "    mMaxStorage.MASS=%I64\n",
        static_cast<std::uint32_t>(massStorageBits & 0xFFFFFFFFu),
        static_cast<std::uint32_t>(massStorageBits >> 32)
      );
      logChecksumDigest();
    }

    if (shouldUpdateReconChecksum) {
      Logf("    CAiReconDBImpl::UpdateSimChecksum()\n");
      army->GetReconDB()->UpdateSimChecksum();
    }

    logChecksumDigest();
  }

  Logf("Dirty Entities\n");
  for (Entity* entity : mCoordEntities.owners_member<Entity, &Entity::mCoordNode>()) {
    const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
    mContext.Update(&entityId, sizeof(entityId));
    if (mLog) {
      Logf("  0x%08x\n", entityId);
      logChecksumDigest();
    }

    const float health = entity->Health;
    mContext.Update(&health, sizeof(health));
    if (mLog) {
      Logf("    health: %.1f 0x%08x\n", health, FloatBits(health));
      logChecksumDigest();
    }

    const char* blueprintId = ResolveBlueprintIdCString(entity);
    UpdateChecksumWithNullableCString(mContext, blueprintId);
    if (mLog) {
      Logf("    bp:%s\n", blueprintId ? blueprintId : "");
      logChecksumDigest();
    }

    mContext.Update(&entity->Orientation, 0x1Cu);
    if (mLog) {
      const float* const pos = reinterpret_cast<const float*>(&entity->Position);
      const float* const rot = reinterpret_cast<const float*>(&entity->Orientation);
      Logf(
        "    pos: <%7.2f,%7.2f,%7.2f> [0x%08x 0x%08x 0x%08x]\n",
        pos[0],
        pos[1],
        pos[2],
        FloatBits(pos[0]),
        FloatBits(pos[1]),
        FloatBits(pos[2])
      );
      Logf(
        "    rot: <%7.4f,%7.4f,%7.4f,%7.4f> [0x%08x 0x%08x 0x%08x 0x%08x]\n",
        rot[0],
        rot[1],
        rot[2],
        rot[3],
        FloatBits(rot[0]),
        FloatBits(rot[1]),
        FloatBits(rot[2]),
        FloatBits(rot[3])
      );
      logChecksumDigest();
    }

    Wm3::Vec3f velocity{};
    ReadEntityVelocity(entity, &velocity);
    mContext.Update(&velocity, sizeof(velocity));
    if (mLog) {
      Logf(
        "   vel: <%7.2f,%7.2f,%7.2f> [0x%08x 0x%08x 0x%08x]\n",
        velocity.x,
        velocity.y,
        velocity.z,
        FloatBits(velocity.x),
        FloatBits(velocity.y),
        FloatBits(velocity.z)
      );
      logChecksumDigest();
    }
  }

  constexpr std::size_t kRngMtBytes = sizeof(CMersenneTwister::StateWords);
  static_assert(kRngMtBytes == 0x9C0u, "Mt19937 payload must remain 0x9C0 bytes");
  mContext.Update(&mRngState->twister.state[0], static_cast<unsigned int>(kRngMtBytes));
  mContext.Update(&mRngState->hasMarsagliaPair, 1u);
  if (mRngState->hasMarsagliaPair) {
    mContext.Update(&mRngState->marsagliaPair, 4u);
  }
}

/**
 * Address: 0x00746790 (FUN_00746790, ??0CDebugCanvas@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes all debug-geometry/text/decal buffers to empty.
 */
CDebugCanvas::CDebugCanvas()
  : lines()
  , worldText()
  , screenText()
  , decals()
{}

/**
 * Address: 0x00756C30 (FUN_00756C30, ??1CDebugCanvas@Moho@@QAE@XZ)
 *
 * What it does:
 * Releases all debug line/text/decal vector storage lanes.
 */
CDebugCanvas::~CDebugCanvas() = default;

/**
 * Address: 0x00452070 (FUN_00452070, Moho::CDebugCanvas::DebugDrawLine)
 */
void CDebugCanvas::DebugDrawLine(const SDebugLine& line)
{
  lines.push_back(line);
}

/**
 * Address: 0x00652C00 (FUN_00652C00, Moho::CDebugCanvas::AddText)
 *
 * What it does:
 * Builds one world-space text entry from position/text/style/depth lanes
 * and appends it to the debug world-text buffer.
 */
void CDebugCanvas::AddText(
  const Wm3::Vector3f& position,
  const char* const text,
  const std::int32_t style,
  const std::uint32_t depth
)
{
  SDebugWorldText entry{};
  entry.position = position;
  entry.text.assign_owned(text != nullptr ? text : "");
  entry.style = style;
  entry.depth = depth;
  AddWorldText(entry);
}

namespace
{
  /**
   * Generic (end_ - first_) / sizeof(T) size helper used by the
   * three non-inlined `size()` thunks the binary emits for the
   * `SDebugWorldText`, `SDebugScreenText`, and `SDebugDecal` debug
   * vector specializations. The first-pointer null-guard mirrors
   * the binary's early-out for uninitialized vectors.
   */
  template <class TDebugRecord>
  [[nodiscard]] std::size_t DebugVectorSizeThunk(const msvc8::vector<TDebugRecord>* const vec) noexcept
  {
    const TDebugRecord* const first = vec ? vec->data() : nullptr;
    if (first == nullptr) {
      return 0u;
    }
    return vec->size();
  }
} // namespace

/**
 * Address: 0x00452110 (FUN_00452110, sub_452110)
 *
 * IDA signature:
 * int __thiscall sub_452110(int *this);
 *
 * What it does:
 * Out-of-line `msvc8::vector<SDebugWorldText>::size()` specialization
 * thunk used by `CDebugCanvas::worldText`. Returns zero when the
 * vector's `first_` pointer is still null, matching the binary's
 * early-out; otherwise returns `(last_ - first_) / sizeof(SDebugWorldText)`
 * (element size `0x30`).
 */
std::size_t GetDebugWorldTextCount(const msvc8::vector<SDebugWorldText>* const worldText) noexcept
{
  return DebugVectorSizeThunk<SDebugWorldText>(worldText);
}

/**
 * Address: 0x00452160 (FUN_00452160, sub_452160)
 *
 * IDA signature:
 * int __thiscall sub_452160(int *this);
 *
 * What it does:
 * Out-of-line `msvc8::vector<SDebugScreenText>::size()` specialization
 * thunk (element size `0x48`). Same shape as
 * `GetDebugWorldTextCount`.
 */
std::size_t GetDebugScreenTextCount(const msvc8::vector<SDebugScreenText>* const screenText) noexcept
{
  return DebugVectorSizeThunk<SDebugScreenText>(screenText);
}

/**
 * Address: 0x004521B0 (FUN_004521B0, sub_4521B0)
 *
 * IDA signature:
 * int __thiscall sub_4521B0(int *this);
 *
 * What it does:
 * Out-of-line `msvc8::vector<SDebugDecal>::size()` specialization
 * thunk (element size `0x34`). Same shape as
 * `GetDebugWorldTextCount`.
 */
std::size_t GetDebugDecalCount(const msvc8::vector<SDebugDecal>* const decals) noexcept
{
  return DebugVectorSizeThunk<SDebugDecal>(decals);
}

/**
 * Address: 0x006531D0 (FUN_006531D0, helper used by Moho::RDebugWeapons::OnTick)
 */
void CDebugCanvas::AddWorldText(const SDebugWorldText& text)
{
  worldText.push_back(text);
}

/**
 * Address: 0x0044F880 (FUN_0044F880, Moho::QuatCrossAdd)
 *
 * What it does:
 * Builds a quaternion that rotates normalized `v1` toward normalized `v2`.
 *
 * Re-derived term-by-term from `FUN_0044F880.c`: the previous body here put
 * the dot-product (scalar) term in `.w` and the three cross-product terms in
 * `.x/.y/.z` -- textbook `.w`-scalar convention. The real disassembly writes
 * the dot product to `.x` and the cross-product terms to `.y/.z/.w`, matching
 * this engine's actual `.x`-is-scalar convention (`VMatrix4::Set`,
 * `QuatToMatrix`, `Moho::MultQuadVec`) -- confirmed load-bearing since every
 * caller of this function feeds the result straight into `MultQuadVec`
 * (e.g. `CDebugCanvas::AddWireCircle` below, `CD3DPrimBatcher::DRAW_Circle`).
 * The zero-length-sum fallback had the same lane shift: ground truth writes
 * the antiparallel-axis fallback as `.x = 0` (scalar half of a 180-degree
 * rotation) and `{.y,.z,.w} = v1`, not `.w = 0` / `{.x,.y,.z} = v1`.
 */
Wm3::Quaternionf* QuatCrossAdd(Wm3::Quaternionf* dest, Wm3::Vector3f v1, Wm3::Vector3f v2)
{
  if (!dest) {
    return nullptr;
  }

  Wm3::Vector3f::Normalize(&v1);
  Wm3::Vector3f::Normalize(&v2);

  Wm3::Vector3f add{
    v2.x + v1.x,
    v1.y + v2.y,
    v1.z + v2.z,
  };

  if (Wm3::Vector3f::Normalize(&add) <= 0.0f) {
    Wm3::Vector3f::Normalize(&v1);
    dest->x = 0.0f;
    dest->y = v1.x;
    dest->z = v1.y;
    dest->w = v1.z;
    return dest;
  }

  dest->x = (add.x * v1.x) + (add.y * v1.y) + (add.z * v1.z);
  dest->y = (add.z * v1.y) - (v1.z * add.y);
  dest->z = (v1.z * add.x) - (add.z * v1.x);
  dest->w = (add.y * v1.x) - (v1.y * add.x);
  return dest;
}

/**
 * Address: 0x00450030 (FUN_00450030, ?AddWireCircle@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MII@Z)
 */
void CDebugCanvas::AddWireCircle(
  const Wm3::Vector3f& normal,
  const Wm3::Vector3f& center,
  const float radius,
  const std::uint32_t depth,
  const std::uint32_t precision
)
{
  Wm3::Quaternionf orientation{};
  QuatCrossAdd(&orientation, {0.0f, 1.0f, 0.0f}, normal);

  Wm3::Vector3f axis2Input{0.0f, radius, 0.0f};
  Wm3::Vector3f axis2{};
  MultQuadVec(&axis2, &axis2Input, &orientation);

  Wm3::Vector3f axis1Input{radius, 0.0f, 0.0f};
  Wm3::Vector3f axis1{};
  MultQuadVec(&axis1, &axis1Input, &orientation);

  AddWireOval(center, axis1, axis2, depth, precision);
}

/**
 * Address: 0x0044FA70 (FUN_0044FA70, ?AddLine@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0I@Z)
 */
void CDebugCanvas::AddLine(const Wm3::Vector3f& p0, const Wm3::Vector3f& p1, const std::uint32_t depth)
{
  SDebugLine line{};
  line.p0 = p0;
  line.p1 = p1;
  line.depth0 = static_cast<std::int32_t>(depth);
  line.depth1 = static_cast<std::int32_t>(depth);
  DebugDrawLine(line);
}

/**
 * Address: 0x0044FD50 (FUN_0044FD50, ?AddContouredLine@CDebugCanvas@Moho@@QAEXABV?$Vector2@M@Wm3@@0IABVCHeightField@2@@Z)
 */
void CDebugCanvas::AddContouredLine(
  const Wm3::Vector2f& p0,
  const Wm3::Vector2f& p1,
  const std::uint32_t depth,
  const CHeightField& heightField
)
{
  const float stepX = (p0.x - p1.x) * 0.1f;
  const float stepZ = (p0.y - p1.y) * 0.1f;

  float prevX = p1.x;
  float prevZ = p1.y;
  float prevY = heightField.GetElevation(p1.x, p1.y);

  for (int i = 0; i < 10; ++i) {
    const float nextX = prevX + stepX;
    const float nextZ = prevZ + stepZ;

    if (static_cast<int>(nextX) > (heightField.width - 1)) {
      break;
    }
    if (static_cast<int>(nextZ) > (heightField.height - 1)) {
      break;
    }

    const float nextY = heightField.GetElevation(nextX, nextZ);
    AddLine({prevX, prevY, prevZ}, {nextX, nextY, nextZ}, depth);

    prevX = nextX;
    prevY = nextY;
    prevZ = nextZ;
  }
}

/**
 * Address: 0x0044FED0 (FUN_0044FED0, ?AddWireOval@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@00II@Z)
 */
void CDebugCanvas::AddWireOval(
  const Wm3::Vector3f& center,
  const Wm3::Vector3f& axis1,
  const Wm3::Vector3f& axis2,
  const std::uint32_t depth,
  const std::uint32_t precision
)
{
  constexpr float kTwoPi = 6.2831855f;

  float prevX = center.x + axis1.x;
  float prevY = center.y + axis1.y;
  float prevZ = center.z + axis1.z;

  for (std::uint32_t i = 1; i <= precision; ++i) {
    const float angle = (static_cast<float>(i) * kTwoPi) / static_cast<float>(precision);
    const float sinAngle = static_cast<float>(std::sin(angle));
    const float cosAngle = static_cast<float>(std::cos(angle));

    const float nextX = center.x + (axis1.x * cosAngle) + (axis2.x * sinAngle);
    const float nextY = center.y + (axis1.y * cosAngle) + (axis2.y * sinAngle);
    const float nextZ = center.z + (axis1.z * cosAngle) + (axis2.z * sinAngle);

    AddLine({prevX, prevY, prevZ}, {nextX, nextY, nextZ}, depth);

    prevX = nextX;
    prevY = nextY;
    prevZ = nextZ;
  }
}

/**
 * Address: 0x00450110 (FUN_00450110, ?AddWireSphere@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MIHHH@Z)
 */
void CDebugCanvas::AddWireSphere(
  const Wm3::Vector3f& center,
  const Wm3::Vector3f& upAxis,
  const float radius,
  const std::uint32_t depth,
  const int unused0,
  const int unused1,
  const int unused2
)
{
  (void)unused0;
  (void)unused1;
  (void)unused2;

  Wm3::Quaternionf orientation{};
  QuatCrossAdd(&orientation, {0.0f, 1.0f, 0.0f}, upAxis);

  Wm3::Vector3f basisX{};
  const Wm3::Vector3f unitX{1.0f, 0.0f, 0.0f};
  MultQuadVec(&basisX, &unitX, &orientation);

  Wm3::Vector3f basisY{};
  const Wm3::Vector3f unitY{0.0f, 1.0f, 0.0f};
  MultQuadVec(&basisY, &unitY, &orientation);

  constexpr float kPiOver4 = 0.78539819f;
  for (int i = 0; i < 4; ++i) {
    const float angle = static_cast<float>(i) * kPiOver4;
    const float sinAngle = static_cast<float>(std::sin(angle));
    const float cosAngle = static_cast<float>(std::cos(angle));

    const Wm3::Vector3f dir{
      (basisX.x * cosAngle) + (basisY.x * sinAngle),
      (basisX.y * cosAngle) + (basisY.y * sinAngle),
      (basisX.z * cosAngle) + (basisY.z * sinAngle),
    };

    AddWireCircle(dir, center, radius, depth, 0x18u);
  }

  for (int i = 1; i <= 3; ++i) {
    const float angle = static_cast<float>(i) * kPiOver4;
    const float centerScale = static_cast<float>(std::cos(angle)) * radius;
    const Wm3::Vector3f ringCenter{
      center.x + (upAxis.x * centerScale),
      center.y + (upAxis.y * centerScale),
      center.z + (upAxis.z * centerScale),
    };
    const float ringRadius = radius * static_cast<float>(std::sin(angle));

    AddWireCircle(upAxis, ringCenter, ringRadius, depth, 0x18u);
  }
}

/**
 * Address: 0x00450330 (FUN_00450330, ?AddWireCoords@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@M@Z)
 */
void CDebugCanvas::AddWireCoords(
  const Wm3::Vector3f& origin,
  const Wm3::Quaternionf& orientation,
  const float axisLength
)
{
  Wm3::Vector3f rotatedAxis{};

  Wm3::Vector3f axisX{axisLength, 0.0f, 0.0f};
  MultQuadVec(&rotatedAxis, &axisX, &orientation);
  AddLine(
    origin,
    {origin.x + rotatedAxis.x, origin.y + rotatedAxis.y, origin.z + rotatedAxis.z},
    static_cast<std::uint32_t>(0xFFFF0000u)
  );

  Wm3::Vector3f axisY{0.0f, axisLength, 0.0f};
  MultQuadVec(&rotatedAxis, &axisY, &orientation);
  AddLine(
    origin,
    {origin.x + rotatedAxis.x, origin.y + rotatedAxis.y, origin.z + rotatedAxis.z},
    static_cast<std::uint32_t>(0xFF00FF00u)
  );

  Wm3::Vector3f axisZ{0.0f, 0.0f, axisLength};
  MultQuadVec(&rotatedAxis, &axisZ, &orientation);
  AddLine(
    origin,
    {origin.x + rotatedAxis.x, origin.y + rotatedAxis.y, origin.z + rotatedAxis.z},
    static_cast<std::uint32_t>(0xFF0000FFu)
  );
}

/**
 * Address: 0x00450500 (FUN_00450500, ?AddWireCoords@CDebugCanvas@Moho@@QAEXABVVTransform@2@M@Z)
 */
void CDebugCanvas::AddWireCoords(const VTransform& transform, const float axisLength)
{
  (void)axisLength;
  AddWireCoords(transform.pos_, transform.orient_, 1.0f);
}

/**
 * Address: 0x00450520 (FUN_00450520, ?AddWireBox@CDebugCanvas@Moho@@QAEXABV?$Box3@M@Wm3@@I@Z)
 */
void CDebugCanvas::AddWireBox(const Wm3::Box3f& box, const std::uint32_t depth)
{
  const Wm3::Vector3f center{box.Center[0], box.Center[1], box.Center[2]};
  const Wm3::Vector3f axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
  const Wm3::Vector3f axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
  const Wm3::Vector3f axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

  const Wm3::Vector3f e0 = axis0 * box.Extent[0];
  const Wm3::Vector3f e1 = axis1 * box.Extent[1];
  const Wm3::Vector3f e2 = axis2 * box.Extent[2];

  const Wm3::Vector3f c000 = center - e0 - e1 - e2;
  const Wm3::Vector3f c001 = center - e0 - e1 + e2;
  const Wm3::Vector3f c010 = center - e0 + e1 - e2;
  const Wm3::Vector3f c011 = center - e0 + e1 + e2;
  const Wm3::Vector3f c100 = center + e0 - e1 - e2;
  const Wm3::Vector3f c101 = center + e0 - e1 + e2;
  const Wm3::Vector3f c110 = center + e0 + e1 - e2;
  const Wm3::Vector3f c111 = center + e0 + e1 + e2;

  AddLine(c000, c001, depth);
  AddLine(c001, c011, depth);
  AddLine(c011, c010, depth);
  AddLine(c010, c000, depth);

  AddLine(c100, c101, depth);
  AddLine(c101, c111, depth);
  AddLine(c111, c110, depth);
  AddLine(c110, c100, depth);

  AddLine(c000, c100, depth);
  AddLine(c001, c101, depth);
  AddLine(c011, c111, depth);
  AddLine(c010, c110, depth);
}

/**
 * Address: 0x00451320 (FUN_00451320, ?AddParabolaClosedForm@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@0MMM@Z)
 */
void CDebugCanvas::AddParabolaClosedForm(
  const Wm3::Vector3f& endPoint,
  const Wm3::Vector3f& startPoint,
  const float angle,
  const float speed,
  const float gravity
)
{
  const float dx = endPoint.x - startPoint.x;
  const float dz = endPoint.z - startPoint.z;

  Wm3::Vector3f direction{dx, 0.0f, dz};
  const float horizontalSpeed = static_cast<float>(std::cos(angle)) * speed;
  const float totalTime = std::sqrt((dx * dx) + (dz * dz)) / horizontalSpeed;
  Wm3::Vector3f::Normalize(&direction);

  const float launchVertical = static_cast<float>(std::sin(angle)) * speed;
  const float halfGravity = gravity * 0.5f;

  float previousX = startPoint.x;
  float previousY = startPoint.y;
  float previousZ = startPoint.z;
  float t = 0.1f;

  if (totalTime >= 0.1f) {
    while (true) {
      const float yOffset = ((t * halfGravity) + launchVertical) * t;
      const float horizontalDistance = t * horizontalSpeed;

      const float nextX = startPoint.x + (horizontalDistance * direction.x);
      const float nextY = startPoint.y + (horizontalDistance * direction.y) + yOffset;
      const float nextZ = startPoint.z + (horizontalDistance * direction.z);

      AddLine(
        {previousX, previousY, previousZ},
        {nextX, nextY, nextZ},
        static_cast<std::uint32_t>(0xFFFFFFFFu)
      );

      const float nextT = t + 0.1f;
      previousX = nextX;
      previousY = nextY;
      previousZ = nextZ;
      t = nextT;

      if (totalTime < nextT) {
        break;
      }
    }
  }
}

/**
 * Address: 0x004514E0 (FUN_004514E0, ?AddParabolaStepped@CDebugCanvas@Moho@@QAEXABV?$Vector3@M@Wm3@@000@Z)
 */
void CDebugCanvas::AddParabolaStepped(
  const Wm3::Vector3f& velocityStep,
  const Wm3::Vector3f& startPoint,
  const Wm3::Vector3f& endPoint,
  const Wm3::Vector3f& accelerationStep
)
{
  Wm3::Vector3f stepVelocity = velocityStep;

  const float horizontalDistance =
    std::sqrt(((endPoint.z - startPoint.z) * (endPoint.z - startPoint.z)) + ((endPoint.x - startPoint.x) * (endPoint.x - startPoint.x)));
  const float horizontalStepLength = std::sqrt((stepVelocity.z * stepVelocity.z) + (stepVelocity.x * stepVelocity.x));
  if (horizontalStepLength <= 0.0f) {
    return;
  }

  const float steps = horizontalDistance / horizontalStepLength;
  if (steps < 1.0f) {
    return;
  }

  float currentX = startPoint.x;
  float currentY = startPoint.y;
  float currentZ = startPoint.z;

  int stepIndex = 1;
  while (true) {
    const float previousVelocityX = stepVelocity.x;
    const float previousVelocityY = stepVelocity.y;
    const float previousVelocityZ = stepVelocity.z;

    stepVelocity.x += accelerationStep.x;
    stepVelocity.y += accelerationStep.y;
    stepVelocity.z += accelerationStep.z;

    const float nextX = currentX + ((previousVelocityX + stepVelocity.x) * 0.5f);
    const float nextY = currentY + ((previousVelocityY + stepVelocity.y) * 0.5f);
    const float nextZ = currentZ + ((previousVelocityZ + stepVelocity.z) * 0.5f);

    SDebugLine line{};
    line.p0 = {currentX, currentY, currentZ};
    line.p1 = {nextX, nextY, nextZ};
    line.depth0 = static_cast<std::int32_t>(0xFF00FFFFu);
    line.depth1 = static_cast<std::int32_t>(0xFF00FFFFu);
    DebugDrawLine(line);

    currentX = nextX;
    currentY = nextY;
    currentZ = nextZ;
    ++stepIndex;
    if (steps < static_cast<float>(stepIndex)) {
      break;
    }
  }
}

/**
 * Address: 0x004516C0 (FUN_004516C0, ?Render@CDebugCanvas@Moho@@QBEXPAVCD3DPrimBatcher@2@ABVGeomCamera3@2@HH@Z)
 */
void CDebugCanvas::Render(
  CD3DPrimBatcher* const primBatcher,
  const GeomCamera3& camera,
  const int viewportWidth,
  const int viewportHeight
) const
{
  if (primBatcher == nullptr) {
    return;
  }

  if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
    device->SelectFxFile("primbatcher");
    device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");
  }

  primBatcher->SetProjectionMatrix(camera.projection);
  primBatcher->SetViewMatrix(camera.view);
  primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

  for (const SDebugLine& line : lines) {
    CD3DPrimBatcher::Vertex start{};
    start.mX = line.p0.x;
    start.mY = line.p0.y;
    start.mZ = line.p0.z;
    start.mColor = static_cast<std::uint32_t>(line.depth0);
    start.mU = 0.0f;
    start.mV = 0.0f;

    CD3DPrimBatcher::Vertex end{};
    end.mX = line.p1.x;
    end.mY = line.p1.y;
    end.mZ = line.p1.z;
    end.mColor = static_cast<std::uint32_t>(line.depth1);
    end.mU = 1.0f;
    end.mV = 0.0f;

    primBatcher->DrawLine(start, end);
  }

  constexpr float kNoMaxAdvance = std::numeric_limits<float>::quiet_NaN();
  for (const SDebugScreenText& text : screenText) {
    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(text.pointSize, "Ariel");
    CD3DFont* const font = rawFont.px;
    if (font != nullptr) {
      (void)font->Render(text.text.raw_data_unsafe(), primBatcher, text.origin, text.xAxis, text.yAxis, text.color, 0.0f, kNoMaxAdvance);
    }
    rawFont.release();
  }

  for (const SDebugDecal& decal : decals) {
    primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(decal.color));

    CD3DPrimBatcher::Vertex corner0{};
    corner0.mX = decal.corner0.x;
    corner0.mY = decal.corner0.y;
    corner0.mZ = decal.corner0.z;
    corner0.mColor = 0xFFFFFFFFu;
    corner0.mU = 0.0f;
    corner0.mV = 0.0f;

    CD3DPrimBatcher::Vertex corner1{};
    corner1.mX = decal.corner1.x;
    corner1.mY = decal.corner1.y;
    corner1.mZ = decal.corner1.z;
    corner1.mColor = 0xFFFFFFFFu;
    corner1.mU = 1.0f;
    corner1.mV = 0.0f;

    CD3DPrimBatcher::Vertex corner2{};
    corner2.mX = decal.corner2.x;
    corner2.mY = decal.corner2.y;
    corner2.mZ = decal.corner2.z;
    corner2.mColor = 0xFFFFFFFFu;
    corner2.mU = 1.0f;
    corner2.mV = 1.0f;

    CD3DPrimBatcher::Vertex corner3{};
    corner3.mX = decal.corner3.x;
    corner3.mY = decal.corner3.y;
    corner3.mZ = decal.corner3.z;
    corner3.mColor = 0xFFFFFFFFu;
    corner3.mU = 0.0f;
    corner3.mV = 1.0f;

    primBatcher->DrawQuad(corner0, corner1, corner2, corner3);
  }

  primBatcher->Flush();

  const float widthF = static_cast<float>(viewportWidth);
  const float heightF = static_cast<float>(viewportHeight);
  VMatrix4 projection{};
  projection.r[0] = {2.0f / widthF, 0.0f, 0.0f, 0.0f};
  projection.r[1] = {0.0f, 2.0f / (-heightF), 0.0f, 0.0f};
  projection.r[2] = {0.0f, 0.0f, -0.5f, 0.0f};
  projection.r[3] = {
    (widthF / (-widthF)) - (1.0f / widthF),
    (heightF / heightF) + (1.0f / heightF),
    0.5f,
    1.0f,
  };

  primBatcher->SetProjectionMatrix(projection);
  primBatcher->SetViewMatrix(VMatrix4::Identity());

  constexpr Wm3::Vector3f kScreenTextXAxis{1.0f, 0.0f, 0.0f};
  constexpr Wm3::Vector3f kScreenTextYAxis{0.0f, -1.0f, 0.0f};
  for (const SDebugWorldText& worldEntry : worldText) {
    const float clipX =
      (worldEntry.position.x * camera.viewProjection.r[0].x) + (worldEntry.position.y * camera.viewProjection.r[1].x) +
      (worldEntry.position.z * camera.viewProjection.r[2].x) + camera.viewProjection.r[3].x;
    const float clipY =
      (worldEntry.position.x * camera.viewProjection.r[0].y) + (worldEntry.position.y * camera.viewProjection.r[1].y) +
      (worldEntry.position.z * camera.viewProjection.r[2].y) + camera.viewProjection.r[3].y;
    const float clipW =
      (worldEntry.position.x * camera.viewProjection.r[0].w) + (worldEntry.position.y * camera.viewProjection.r[1].w) +
      (worldEntry.position.z * camera.viewProjection.r[2].w) + camera.viewProjection.r[3].w;
    const float inverseW = 1.0f / clipW;

    const float ndcX = clipX * inverseW;
    const float ndcY = clipY * inverseW;
    const float screenX = ((ndcX - -1.0f) * widthF) * 0.5f;
    const float screenY = (((ndcY - -1.0f) * (-heightF)) * 0.5f) + heightF;
    const Wm3::Vector3f screenOrigin{
      static_cast<float>(std::floor(screenX)),
      static_cast<float>(std::floor(screenY)),
      0.0f,
    };

    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(worldEntry.style, "Ariel");
    CD3DFont* const font = rawFont.px;
    if (font != nullptr) {
      (void)font->Render(
        worldEntry.text.raw_data_unsafe(),
        primBatcher,
        screenOrigin,
        kScreenTextXAxis,
        kScreenTextYAxis,
        worldEntry.depth,
        0.0f,
        kNoMaxAdvance
      );
    }
    rawFont.release();
  }

  primBatcher->Flush();
}

/**
 * Address: 0x00451FB0 (FUN_00451FB0, ?Clear@CDebugCanvas@Moho@@QAEXXZ)
 */
void CDebugCanvas::Clear()
{
  lines.clear();
  screenText.clear();
  worldText.clear();
  decals.clear();
}

/**
 * Address: 0x00746280 (FUN_00746280, ?Logf@Sim@Moho@@QAAXPBDZZ)
 *
 * What it does:
 * Writes one formatted line into the active sim log stream when logging is enabled.
 */
void Sim::Logf(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  if (mLog) {
    (void)vfprintf(mLog, fmt, args);
  }

  va_end(args);
}

/**
 * Address: 0x007462A0 (FUN_007462A0, ?Printf@Sim@Moho@@QAAXPBDZZ)
 *
 * What it does:
 * Formats one line and appends it into `mPrintField`.
 */
void Sim::Printf(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  const char* format = fmt;
  mPrintField.push_back(gpg::STR_Va(format, args));

  va_end(args);
}

// Global "current sim" singleton and reflection type descriptor.
Sim* Sim::sInstance = nullptr;

/**
 * Address: 0x007434D0 (FUN_007434D0, ??0Sim@Moho@@AAE@PAULaunchInfoBase@1@@Z)
 * Mangled: ??0Sim@Moho@@AAE@PAULaunchInfoBase@1@@Z
 *
 * IDA signature:
 * Moho::Sim *__stdcall Moho::Sim::Sim(Moho::Sim *this, Moho::LaunchInfoBase *info);
 *
 * What it does:
 * Placement-constructed factory constructor. Establishes the full 0xAF8 Sim
 * layout, seeds the command-source vector + focus army from the launch info,
 * optionally opens the synclog file, builds a fresh Lua state, runs the "core"
 * and "sim" init sets, loads `simInit.lua`/`saveload.lua`, loads terrain types,
 * allocates the occupation grid and path tables, then exports the rules to Lua
 * and seeds the rolling sim checksum.
 */
Sim::Sim(LaunchInfoBase* const info)
  : ICommandSink()
  , mLog(nullptr)
  , mIsDesyncFree(true)
  , mEffectManager(nullptr)
  , mSoundManager(nullptr)
  , mRules(info->mGameRules)
  , mMapData(nullptr)
  , mLuaState(nullptr)
  , mGameEnded(false)
  , mGameOver(false)
  , mPausedByCommandSource(-1)
  , mSingleStep(false)
  , mAdvancedThisTick(false)
  , mCheatsEnabled(false)
  , mReserved8E7(false)
  , mCurBeat(0)
  , mDidProcess(true)
  , mCurTick(0)
  , mRngState(nullptr)
  , mOGrid(nullptr)
  , mCurCommandSource(255)
  , mPathTables(nullptr)
  , mFormationDB(nullptr)
  , mCommandDB(nullptr)
  , mEntityDB(nullptr)
  , mReserved98C(0)
  , mReserved990(0)
  , mDecalBuffer(nullptr)
  , mPhysConstants(nullptr)
  , mRequestXMLArmyStatsSubmit(false)
  , mSyncArmy(-1)
  , mDidSync(false)
{
  // POD lanes the compiler does not default-init are cleared here to match the
  // binary's explicit member zeroing.
  mSyncReserveUnused = 0;
  for (std::int32_t& reserveCount : mSyncReserveCounts) {
    reserveCount = 0;
  }
  mContext.Reset();

  // Seed the command-source vector from the launch info block, then mark the
  // "no source" sentinel and adopt the focus army.
  (void)CopyConstructCommandSourceVector(info->mCommandSources.mSrcs, &mCommandSources);

  // Optionally open the per-beat synclog when /synclog was requested.
  msvc8::vector<msvc8::string> synclogArgs;
  if (CFG_GetArgOption("/synclog", 1u, &synclogArgs) && !synclogArgs.empty()) {
    const msvc8::string& synclogDir = synclogArgs.front();
    ::CreateDirectoryA(synclogDir.c_str(), nullptr);

    const msvc8::string filenamePrefix = LOG_GenerateFilenamePrefix();
    const msvc8::string prefixWithSlash = synclogDir + msvc8::string("/");
    mLogFilePrefix.assign(prefixWithSlash + filenamePrefix, 0, msvc8::string::npos);

    ::CreateDirectoryA(mLogFilePrefix.c_str(), nullptr);
    (void)mLogFilePrefix.append("/", 1u);

    const msvc8::string beatFile = FormatBeatLogFilePath(mLogFilePrefix, static_cast<int>(mCurBeat));
    mLog = std::fopen(beatFile.c_str(), "w");
  }

  Logf("********** beat %d **********\n", mCurBeat);

  // Adopt ownership of the map data (moved out of the launch info).
  STIMap* const previousMap = mMapData;
  mMapData = info->mMap;
  info->mMap = nullptr;
  if (previousMap) {
    delete previousMap;
  }

  mSyncFilter.focusArmy = info->mCommandSources.mOriginalSource;

  // Build a fresh Lua state, bind this Sim as the global userdata, and run the
  // registered core + sim init form sets.
  {
    auto* const newState = new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE);
    LuaPlus::LuaState* const previousState = mLuaState;
    mLuaState = newState;
    if (previousState) {
      delete previousState;
    }
  }
  lua_setglobaluserdata(mLuaState->m_state, this);

  if (CScrLuaInitFormSet* const coreSet = SCR_FindLuaInitFormSet("Core"); coreSet != nullptr) {
    coreSet->RunInits(mLuaState);
  }
  if (CScrLuaInitFormSet* const simSet = SCR_FindLuaInitFormSet("Sim"); simSet != nullptr) {
    simSet->RunInits(mLuaState);
  }
  if (SCR_IsDebugWindowActive()) {
    lua_sethook(mLuaState->m_state, &moho::DebugLuaHook, 4, 0);
  }
  mLuaState->m_luaTask = reinterpret_cast<CLuaTask*>(&mDiskWatcherTaskStage);

  {
    gpg::LogScopeEntry luaBpScope(msvc8::string("MEM: %i bytes LUABP"));
    mRules->ExportToLuaState(mLuaState);
    luaBpScope.Emit();
  }

  {
    LuaPlus::LuaObject globals = mLuaState->GetGlobals();
    globals.SetString("__language", info->mLanguage.c_str());
  }

  (void)SCR_LuaDoScript(mLuaState, "/lua/simInit.lua", nullptr);
  (void)SCR_LuaDoScript(mLuaState, "/lua/system/saveload.lua", nullptr);
  mMapData->LoadTerrainTypes(mLuaState);

  // Allocate the occupation grid.
  {
    gpg::LogScopeEntry ogridScope(msvc8::string("MEM: %i bytes OGRID"));
    auto* const newGrid = new COGrid(this);
    COGrid* const previousGrid = mOGrid;
    mOGrid = newGrid;
    if (previousGrid) {
      delete previousGrid;
    }
    ogridScope.Emit();
  }

  // Allocate the path tables sized to the interior of the heightfield.
  {
    CHeightField* const heightField = mMapData->mHeightField.get();
    const std::int32_t interiorWidth = heightField->width - 1;
    const std::int32_t interiorHeight = heightField->height - 1;
    const SRuleFootprintsBlueprint* const footprints = mRules->GetFootprints();
    auto* const newTables = new PathTables(*footprints, mOGrid, interiorWidth, interiorHeight);
    PathTables* const previousTables = mPathTables;
    mPathTables = newTables;
    if (previousTables) {
      delete previousTables;
    }
  }

  // Seed the rolling sim checksum from the rules and log the initial digest.
  mRules->UpdateChecksum(&mContext, mLog);
  const gpg::MD5Digest digest = mContext.Digest();
  Logf("SimChecksum after rules: %s\n", digest.ToString().c_str());
}

/**
 * Address: 0x00744060 (FUN_00744060, ?Setup@Sim@Moho@@AAEXPAVLaunchInfoNew@2@@Z)
 * Mangled: ?Setup@Sim@Moho@@AAEXPAVLaunchInfoNew@2@@Z
 *
 * IDA signature:
 * void __stdcall Moho::Sim::Setup(Moho::Sim *this, Moho::LaunchInfoNew *info);
 *
 * What it does:
 * New-game initialization pass, populating the subsystems the constructor left
 * null and running the Lua `SetupSession`/`BeginSession` callbacks around
 * `CreateArmies`/`PostInitialize`. See the class declaration for the ordered
 * list of subsystems constructed here.
 */
void Sim::Setup(LaunchInfoNew* const info)
{
  mCheatsEnabled = info->mCheatsEnabled;

  // Disk-watcher task, staged on the disk-watcher task stage.
  (void)CTask::CreateTaskThread(new ScrDiskWatcherTask(mLuaState), &mDiskWatcherTaskStage, true);

  // Decal buffer.
  {
    auto* const newDecalBuffer = new CDecalBuffer(this);
    CDecalBuffer* const previousDecalBuffer = mDecalBuffer;
    mDecalBuffer = newDecalBuffer;
    if (previousDecalBuffer) {
      delete previousDecalBuffer;
    }
  }

  // Per-run RNG stream seeded from the launch info.
  {
    auto* const newRng = new CRandomStream(static_cast<std::uint32_t>(info->mInitSeed));
    CRandomStream* const previousRng = mRngState;
    mRngState = newRng;
    if (previousRng) {
      delete previousRng;
    }
  }

  // Physics constants (gravity = (0, -4.9, 0)).
  {
    auto* const newPhys = new SPhysConstants();
    SPhysConstants* const previousPhys = mPhysConstants;
    mPhysConstants = newPhys;
    delete previousPhys;
  }

  // Build the ScenarioInfo.ArmySetup Lua table from the army name/setup strings.
  // The scenario table is deserialized from the launch info's ScenarioInfo blob,
  // and each army's setup table from its entry in the army-setup string vector.
  LuaPlus::LuaObject scenarioInfo{};
  (void)SCR_FromString(&scenarioInfo, info->mScenarioInfo, mLuaState);

  msvc8::vector<LuaPlus::LuaObject> armySetupObjects{};
  LuaPlus::LuaObject armySetupTable{};
  armySetupTable.AssignNewTable(mLuaState, 0, 0);

  const std::size_t armyCount = info->mStrVec.size();
  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    LuaPlus::LuaObject armySetup{};
    (void)SCR_FromString(&armySetup, info->mStrVec.begin()[armyIndex], mLuaState);
    armySetup.SetInteger("ArmyIndex", static_cast<std::int32_t>(armyIndex + 1));
    armySetupObjects.push_back(armySetup);

    const char* const armyName = armySetup["ArmyName"].GetString();
    armySetupTable.SetObject(armyName, armySetup);
  }
  scenarioInfo.SetObject("ArmySetup", armySetupTable);
  mLuaState->GetGlobals().SetObject("ScenarioInfo", scenarioInfo);

  // SetupSession() Lua callback.
  {
    LuaPlus::LuaFunction setupSession(mLuaState->GetGlobal("SetupSession"));
    if (!setupSession.IsFunction()) {
      setupSession.TypeError("call");
    }
    setupSession.Call();
  }

  // Refresh heightfield bounds to the full grid.
  {
    CHeightField* const heightField = mMapData->mHeightField.get();
    const gpg::Rect2i fullBounds{0, 0, 0x7FFFFFFF, 0x7FFFFFFF};
    heightField->UpdateBounds(fullBounds);
  }

  // Formation database.
  {
    auto* const newFormationDB = new CAiFormationDBImpl();
    newFormationDB->mSim = this;
    CAiFormationDBImpl* const previousFormationDB = mFormationDB;
    mFormationDB = newFormationDB;
    if (previousFormationDB) {
      delete previousFormationDB;
    }
  }

  // Sim resources (shared-pointer lane). The binary assigns a freshly-owned
  // control block (use_count = 1); build one via the deleter ctor and transfer
  // ownership into the member (which starts null).
  {
    auto* const newResources = new CSimResources();
    boost::SharedPtrRaw<CSimResources> owningResources(
      newResources, [](CSimResources* const p) noexcept { delete p; });
    mSimResources.px = owningResources.px;
    mSimResources.pi = owningResources.pi;
    owningResources.px = nullptr;
    owningResources.pi = nullptr;
  }

  // Resolve ScenarioInfo.Options for the army/post-init callbacks.
  LuaPlus::LuaObject scenarioInfoOptions = mLuaState->GetGlobals().Lookup("ScenarioInfo.Options");

  // Entity database.
  {
    auto* const newEntityDB = new CEntityDb();
    CEntityDb* const previousEntityDB = mEntityDB;
    mEntityDB = newEntityDB;
    if (previousEntityDB) {
      delete previousEntityDB;
    }
  }

  // Command database.
  {
    auto* const newCommandDB = new CCommandDb(this);
    CCommandDb* const previousCommandDB = mCommandDB;
    mCommandDB = newCommandDB;
    if (previousCommandDB) {
      delete previousCommandDB;
    }
  }

  // Effect manager (interface-owned).
  {
    auto* const newEffectManager = new CEffectManagerImpl(this);
    CEffectManagerImpl* const previousEffectManager = mEffectManager;
    mEffectManager = newEffectManager;
    if (previousEffectManager) {
      delete previousEffectManager;
    }
  }

  // Create the armies from the scenario launch info.
  CreateArmies(info->mArmyLaunchInfo, armySetupObjects, scenarioInfoOptions);

  // Optional sound manager: only when a non-empty engine list is configured and
  // sound is not disabled.
  if (sSoundConfiguration != nullptr && sSoundConfiguration->mEngines.mStart != nullptr &&
      sSoundConfiguration->mEngines.mFinish != sSoundConfiguration->mEngines.mStart &&
      sSoundConfiguration->mNoSound == 0) {
    auto* const newSoundManager = new CSimSoundManager(this);
    CSimSoundManager* const previousSoundManager = mSoundManager;
    mSoundManager = newSoundManager;
    if (previousSoundManager) {
      delete previousSoundManager;
    }
  }

  // Spawn scenario props unless /noprops was requested. Each record's blueprint
  // id is resolved through the rules and instantiated at its stored transform.
  if (!CFG_GetArgOption("/noprops", 0u, nullptr)) {
    CWldProps* const props = info->mProps;
    int propCount = 0;
    if (props != nullptr && props->mEntriesBegin != nullptr) {
      propCount = static_cast<int>(props->mEntriesEnd - props->mEntriesBegin);
      for (const CWldPropEntry* entry = props->mEntriesBegin; entry != props->mEntriesEnd; ++entry) {
        (void)PROP_Create(this, entry->mTransform, entry->mBlueprintPath.c_str());
      }
    }
    gpg::Warnf(" NUM PROPS = %d", propCount);
  }

  // BeginSession() Lua callback.
  {
    LuaPlus::LuaFunction beginSession(mLuaState->GetGlobal("BeginSession"));
    if (!beginSession.IsFunction()) {
      beginSession.TypeError("call");
    }
    beginSession.Call();
  }

  // Final post-initialization pass (prebuilt units, etc.).
  PostInitialize(scenarioInfoOptions);
}

/**
 * Address: 0x007449A0 (FUN_007449A0, ?Load@Sim@Moho@@AAEXPAVLaunchInfoLoad@2@@Z)
 * Mangled: ?Load@Sim@Moho@@AAEXPAVLaunchInfoLoad@2@@Z
 *
 * IDA signature:
 * void __stdcall Moho::Sim::Load(Moho::Sim *this, Moho::LaunchInfoLoad *loadInfo);
 *
 * What it does:
 * Load-game initialization pass. Deserializes this Sim from the saved archive,
 * refreshes heightfield bounds, re-arms every loaded unit's intel handles and
 * re-binds each loaded prop into the entity DB bounded-prop queue, then re-syncs
 * the playable rectangle and fires the `OnPostLoad` Lua callback.
 */
void Sim::Load(LaunchInfoLoad* const loadInfo)
{
  gpg::ReadArchive* const archive = loadInfo->mReadArchive;

  // Deserialize this Sim instance from the saved archive.
  if (!Sim::sType) {
    Sim::sType = gpg::LookupRType(typeid(Sim));
  }
  gpg::RRef ownerRef{};
  archive->Read(Sim::sType, this, ownerRef);
  archive->EndSection(false);

  // Refresh the heightfield bounds to the full grid.
  {
    CHeightField* const heightField = mMapData->mHeightField.get();
    const gpg::Rect2i fullBounds{0, 0, 0x7FFFFFFF, 0x7FFFFFFF};
    heightField->UpdateBounds(fullBounds);
  }

  // Walk every loaded unit: re-arm its intel handles (AddViz) and re-bind any
  // prop entity into the entity DB bounded-prop priority queue.
  for (CUnitIterAllArmies iter(this); iter.mItr != iter.mEnd; iter.Next()) {
    auto* const entity = static_cast<Entity*>(iter.mCur);
    if (!entity) {
      continue;
    }

    if (CIntel* const intel = entity->mIntelManager; intel != nullptr) {
      for (CIntelPosHandle* const handle : intel->mIntelHandles) {
        if (handle) {
          handle->AddViz();
        }
      }
    }

    if (Prop* const prop = entity->IsProp(); prop != nullptr && prop->mHandleIndex != -1) {
      prop->mHandleIndex = mEntityDB->AddBoundedProp(prop);
    }
  }

  // Re-sync the playable rectangle through /lua/SimSync.lua::SyncPlayableRect.
  {
    LuaPlus::LuaObject simSyncModule = SCR_Import(mLuaState, "/lua/SimSync.lua");
    LuaPlus::LuaFunction syncPlayableRect(simSyncModule["SyncPlayableRect"]);
    if (!syncPlayableRect.IsFunction()) {
      syncPlayableRect.TypeError("call");
    }

    const gpg::Rect2i playableRect = mMapData->mPlayableRect;
    const LuaPlus::LuaObject rectObject = SCR_ToLua<gpg::Rect2<int>>(mLuaState, playableRect);
    syncPlayableRect.Call_Object(rectObject);
  }

  // Fire the OnPostLoad Lua callback.
  {
    LuaPlus::LuaFunction onPostLoad(mLuaState->GetGlobal("OnPostLoad"));
    if (!onPostLoad.IsFunction()) {
      onPostLoad.TypeError("call");
    }
    onPostLoad.Call();
  }
}

/**
 * Address: 0x007433B0 (FUN_007433B0,
 * ?Create@Sim@Moho@@SAPAV12@ABV?$shared_ptr@ULaunchInfoBase@Moho@@@boost@@@Z)
 * Mangled: ?Create@Sim@Moho@@SAPAV12@ABV?$shared_ptr@ULaunchInfoBase@Moho@@@boost@@@Z
 *
 * IDA signature:
 * Moho::Sim *__thiscall Moho::Sim::Create(boost::shared_ptr<LaunchInfoBase> *launchInfo);
 *
 * What it does:
 * Factory entry point and coupling hub for the Sim construction chain. Allocates
 * one Sim (operator new of 0xAF8 bytes), constructs it from the launch info,
 * publishes it as the `sInstance` singleton, and dispatches to `Setup` (new
 * game) or `Load` (saved game). Throws `std::runtime_error` when the launch info
 * is neither a `LaunchInfoNew` nor a `LaunchInfoLoad`.
 */
Sim* Sim::Create(const boost::SharedPtrRaw<LaunchInfoBase>& launchInfo)
{
  LaunchInfoBase* const info = launchInfo.px;

  // Allocate + placement-construct the Sim (0xAF8-byte layout). The EH unwind of
  // this `new` expression is what references ~Sim in the binary.
  Sim* const sim = new Sim(info);
  Sim::sInstance = sim;

  if (LaunchInfoNew* const newInfo = info->GetNew(); newInfo != nullptr) {
    sim->Setup(newInfo);
    return sim;
  }

  if (LaunchInfoLoad* const loadInfo = info->GetLoad(); loadInfo != nullptr) {
    sim->Load(loadInfo);
    return sim;
  }

  const msvc8::string message =
    gpg::STR_Printf("Unknown subclass of LaunchInfoBase: %s", typeid(*info).name());
  throw std::runtime_error(message.c_str());
}

/**
 * Address: 0x007458E0 (FUN_007458E0, ??1Sim@Moho@@UAE@XZ)
 * Mangled: ??1Sim@Moho@@UAE@XZ
 *
 * IDA signature:
 * void __stdcall Moho::Sim::~Sim(Moho::Sim *this);
 *
 * What it does:
 * Reverse-construction teardown. Stops the task stages, deletes every owned
 * subsystem (formation/effect/decal/sound/entity/command DBs, occupation grid,
 * path tables, RNG, sim vars, physics constants, map, Lua state), rotates and
 * deletes retained synclog files, cancels the rules Lua export, and drains the
 * per-beat pending-ref slot lane. All container / shared_ptr / task-stage
 * members are destroyed automatically after this body runs; the singleton
 * pointer is cleared.
 */
Sim::~Sim()
{
  // Stop the three task stages (disk-watcher + two sim task stages).
  mDiskWatcherTaskStage.Teardown();
  mTaskStageA.Teardown();
  mTaskStageB.Teardown();

  // Formation DB (interface-owned; virtual delete).
  if (mFormationDB) {
    delete mFormationDB;
    mFormationDB = nullptr;
  }

  // Occupation grid.
  if (mOGrid) {
    delete mOGrid;
    mOGrid = nullptr;
  }

  // Command DB.
  if (mCommandDB) {
    delete mCommandDB;
    mCommandDB = nullptr;
  }

  // Armies (each entry owned).
  for (std::size_t i = 0; i < mArmiesList.size(); ++i) {
    if (mArmiesList[i]) {
      delete mArmiesList[i];
      mArmiesList[i] = nullptr;
    }
  }

  // Entity DB.
  if (mEntityDB) {
    delete mEntityDB;
    mEntityDB = nullptr;
  }

  // Random stream (raw storage; no destructor in the binary).
  if (mRngState) {
    delete mRngState;
    mRngState = nullptr;
  }

  // Path tables.
  if (mPathTables) {
    delete mPathTables;
    mPathTables = nullptr;
  }

  // Sim convar instances (interface-owned).
  for (CSimConVarInstanceBase*& simVar : mSimVars) {
    if (simVar) {
      delete simVar;
      simVar = nullptr;
    }
  }

  // Effect manager (interface-owned).
  if (mEffectManager) {
    delete mEffectManager;
    mEffectManager = nullptr;
  }

  // Decal buffer.
  if (mDecalBuffer) {
    delete mDecalBuffer;
    mDecalBuffer = nullptr;
  }

  // Sound manager (interface-owned).
  if (mSoundManager) {
    delete mSoundManager;
    mSoundManager = nullptr;
  }

  // Close and rotate the synclog: retain the current line for desync-free runs,
  // then delete each retained log file recorded in mDesyncLogLines.
  if (mLog) {
    std::fclose(mLog);
    mLog = nullptr;
    if (mIsDesyncFree) {
      mDesyncLogLines.push_back(mDesyncLogLine);
    }
  }
  while (!mDesyncLogLines.empty()) {
    const msvc8::string logFile = mDesyncLogLines.front();
    (void)mDesyncLogLines.erase(mDesyncLogLines.begin());
    if (!::DeleteFileA(logFile.c_str())) {
      gpg::Warnf("Error deleting sim log file: %s", logFile.c_str());
    }
  }

  // Cancel the rules Lua export, then destroy the Lua state.
  mRules->CancelExport(mLuaState);
  if (mLuaState) {
    delete mLuaState;
    mLuaState = nullptr;
  }

  // Clear the global "current sim" singleton (before member teardown, matching
  // the binary ordering).
  Sim::sInstance = nullptr;

  // Drain the deletion-queue pending-ref slot lane. `mDeletionQueue` (an
  // msvc8::deque) is layout-identical to PointerSlotCollectionRuntimeView
  // (_Map/_Mapsize/_Myoff/_Mysize map to slots/slotCount/ownerRefOrState/
  // pendingRefCount), which is what the binary's sub_74DF10 drains at +0xA48.
  DrainPendingRefsAndReleasePointerSlots(
    reinterpret_cast<PointerSlotCollectionRuntimeView*>(&mDeletionQueue));

  // Physics constants (raw storage).
  if (mPhysConstants) {
    delete mPhysConstants;
    mPhysConstants = nullptr;
  }

  // Map data.
  if (mMapData) {
    delete mMapData;
    mMapData = nullptr;
  }

  // Remaining container / shared_ptr / task-stage / sync-filter members are
  // destroyed by their own destructors after this body returns, matching the
  // binary's compiler-generated member teardown pass.
}

/**
 * Address: 0x00746310 (FUN_00746310,
 * ?CreateArmies@Sim@Moho@@QAEXABV?$vector@UArmyLaunchInfo@Moho@@V?$allocator@UArmyLaunchInfo@Moho@@@std@@@std@@ABV?$vector@VLuaObject@LuaPlus@@V?$allocator@VLuaObject@LuaPlus@@@std@@@4@ABVLuaObject@LuaPlus@@@Z)
 *
 * IDA signature:
 * void __stdcall Moho::Sim::CreateArmies(Sim *this,
 *                                        std::vector<ArmyLaunchInfo> const *launchInfo,
 *                                        std::vector<LuaObject> const *armySetupObjects,
 *                                        LuaObject const *scenarioInfoOptions);
 *
 * What it does:
 * Resizes `mArmiesList` to the number of scenario army-launch entries, allocates
 * one `CArmyImpl` per slot via `AllocateScenarioArmy`, then fires the Lua
 * `OnCreateArmyBrain(armyIndex+1, brain, armyName, playerName)` callback per
 * army with a `try/Warnf` guard. The focus-army flag passed into the allocator
 * is true when the iteration index equals `mSyncFilter.focusArmy`.
 */
void Sim::CreateArmies(
  const msvc8::vector<ArmyLaunchInfo>& launchInfo,
  const msvc8::vector<LuaPlus::LuaObject>& armySetupObjects,
  const LuaPlus::LuaObject& scenarioInfoOptions
)
{
  const std::size_t armyCount = launchInfo.size();
  mArmiesList.resize(armyCount);

  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    const bool isFocusArmy =
      (static_cast<std::int32_t>(armyIndex) == mSyncFilter.focusArmy);

    CArmyImpl* const army = AllocateScenarioArmy(
      this,
      static_cast<std::int32_t>(armyIndex),
      launchInfo[armyIndex],
      armySetupObjects[armyIndex],
      scenarioInfoOptions,
      isFocusArmy
    );
    mArmiesList[armyIndex] = army;

    try {
      const LuaPlus::LuaObject globals = mLuaState->GetGlobals();
      const LuaPlus::LuaFunction<> onCreateArmyBrain(globals["OnCreateArmyBrain"]);
      CAiBrain* const brain = army->GetArmyBrain();
      onCreateArmyBrain.Call_IntBrainStr2(
        static_cast<unsigned int>(armyIndex + 1),
        brain != nullptr ? &brain->mLuaObj : nullptr,
        army->ArmyName.c_str(),
        army->PlayerName.c_str()
      );
    } catch (const std::exception& ex) {
      gpg::Warnf("Error running OnCreateArmyBrain: %s", ex.what());
    }
  }
}

/**
 * Address: 0x007464D0 (FUN_007464D0, ?PostInitialize@Sim@Moho@@QAEXABVLuaObject@LuaPlus@@@Z)
 *
 * What it does:
 * Checks launch option `PrebuiltUnits`; when enabled (`"On"`), calls the
 * global Lua function `InitializePrebuiltUnits` once for each non-civilian
 * army using the army name string.
 */
void Sim::PostInitialize(const LuaPlus::LuaObject& launchOptions)
{
  const LuaPlus::LuaObject prebuiltUnitsOption = launchOptions["PrebuiltUnits"];
  if (prebuiltUnitsOption.IsNil()) {
    return;
  }

  const std::string prebuiltUnitsMode(prebuiltUnitsOption.GetString());
  if (prebuiltUnitsMode != "On") {
    return;
  }

  for (CArmyImpl* const army : mArmiesList) {
    if (army->IsCivilian != 0u) {
      continue;
    }

    const LuaPlus::LuaObject globals = mLuaState->GetGlobals();
    const LuaPlus::LuaFunction<> initializePrebuiltUnits(globals["InitializePrebuiltUnits"]);
    try {
      initializePrebuiltUnits(army->ArmyName.c_str());
    } catch (const std::exception& ex) {
      gpg::Warnf("Error running InitializePrebuiltUnits: %s", ex.what());
    }
  }
}

/**
 * Address: 0x00545A40 (FUN_00545A40, ?GetResources@Sim@Moho@@QBEPBVISimResources@2@XZ)
 *
 * What it does:
 * Returns the currently bound simulation resources interface lane.
 */
const ISimResources* Sim::GetResources() const
{
  return mSimResources.px;
}

/**
 * Address: 0x00746720 (FUN_00746720, ?GetDebugCanvas@Sim@Moho@@QAEPAVCDebugCanvas@2@XZ)
 */
CDebugCanvas* Sim::GetDebugCanvas()
{
  if (!mDebugCanvas1) {
    mDebugCanvas1.reset(new CDebugCanvas());
  }
  return mDebugCanvas1.get();
}

/**
 * Address: 0x007467F0 (FUN_007467F0, ?RegisterEntitySet@Sim@Moho@@QAEXPAVEntitySetBase@2@@Z)
 *
 * What it does:
 * Unlinks one entity-set node from its current ring and inserts it into the
 * sim EntityDB registered-set list.
 */
void Sim::RegisterEntitySet(EntitySetBase* const set)
{
  if (!set || !mEntityDB) {
    return;
  }

  mEntityDB->RegisterEntitySet(*set);
}

/**
 * Address: 0x007538C0 (FUN_007538C0, boost::shared_ptr_SParticleBuffer::shared_ptr_SParticleBuffer)
 *
 * What it does:
 * Constructs one `shared_ptr<SParticleBuffer>` from one raw particle-buffer
 * pointer lane.
 */
boost::shared_ptr<SParticleBuffer>* ConstructSharedParticleBufferFromRaw(
  boost::shared_ptr<SParticleBuffer>* const outBuffer,
  SParticleBuffer* const buffer
)
{
  return ::new (outBuffer) boost::shared_ptr<SParticleBuffer>(buffer);
}

/**
 * Address: 0x00751220 (FUN_00751220, boost::shared_ptr_SParticleBuffer::operator=)
 *
 * What it does:
 * Rebinds one `shared_ptr<SParticleBuffer>` from a raw pointer and releases
 * prior ownership.
 */
boost::shared_ptr<SParticleBuffer>* AssignSharedParticleBufferFromRaw(
  boost::shared_ptr<SParticleBuffer>* const outBuffer,
  SParticleBuffer* const buffer
)
{
  outBuffer->reset(buffer);
  return outBuffer;
}

/**
 * Address: 0x00743180 (FUN_00743180)
 *
 * What it does:
 * Copies one `shared_ptr<CHeightField>` lane and retains the control block.
 */
boost::shared_ptr<CHeightField>* CopySharedHeightFieldPtr(
  boost::shared_ptr<CHeightField>* const destination,
  const boost::shared_ptr<CHeightField>* const source
)
{
  if (destination == nullptr || source == nullptr) {
    return destination;
  }

  *destination = *source;
  return destination;
}

/**
 * Address: 0x00746820 (FUN_00746820, ?GetParticleBuffer@Sim@Moho@@QAEPAUSParticleBuffer@2@XZ)
 *
 * What it does:
 * Returns the shared particle buffer, allocating and binding it lazily on
 * first use.
 */
SParticleBuffer* Sim::GetParticleBuffer()
{
  if (!mParticleBuffer) {
    (void)AssignSharedParticleBufferFromRaw(&mParticleBuffer, new SParticleBuffer());
  }

  return mParticleBuffer.get();
}

/**
 * Address: 0x007466D0 (FUN_007466D0, ?GetCurrentCommandSource@Sim@Moho@@QBEPBUSSTICommandSource@2@XZ)
 *
 * What it does:
 * Returns the current command-source lane, or `nullptr` for sentinel id.
 */
const SSTICommandSource* Sim::GetCurrentCommandSource() const
{
  const CommandSourceId sourceId = static_cast<CommandSourceId>(mCurCommandSource);
  if (sourceId == kInvalidCommandSource) {
    return nullptr;
  }

  return &mCommandSources[static_cast<std::size_t>(sourceId)];
}

/**
 * Address: 0x007466F0 (FUN_007466F0, ?GetCurrentCommandSourceName@Sim@Moho@@QBEPBDXZ)
 *
 * What it does:
 * Returns current command-source name or fallback sentinel text when source id is invalid.
 */
const char* Sim::GetCurrentCommandSourceName() const
{
  const SSTICommandSource* const source = GetCurrentCommandSource();
  if (!source) {
    return "???";
  }

  return source->mName.c_str();
}

/**
 * Address: 0x0062CBD0 (FUN_0062CBD0, ?CenterOfMap@Sim@Moho@@QBE?AV?$Vector3@M@Wm3@@XZ)
 *
 * What it does:
 * Computes the center of the current map in terrain grid coordinates from
 * the backing heightfield dimensions and returns a zero-elevation vector.
 */
Wm3::Vec3f Sim::CenterOfMap() const
{
  const CHeightField* const field = mMapData->GetHeightField();

  Wm3::Vec3f center{};
  center.x = static_cast<float>(field->width - 1) * 0.5f;
  center.y = 0.0f;
  center.z = static_cast<float>(field->height - 1) * 0.5f;
  return center;
}

LuaPlus::LuaState* Sim::GetLuaState() const noexcept
{
  return mLuaState;
}

// 0x00747180
bool Sim::CheatsEnabled()
{
  if (mCheatsEnabled) {
    if (IsSimReportCheatsEnabled()) {
      gpg::Warnf("%s is cheating!", GetCurrentCommandSourceName());
    }
  } else {
    gpg::Warnf("%s is trying to cheat!", GetCurrentCommandSourceName());
  }

  if (IsSimDebugCheatsEnabled()) {
    struct CallStackScratch
    {
      unsigned int a3[2];
      unsigned int a4[15];
    };

    CallStackScratch scratch{};
    msvc8::string callstackText{};

    const int frameCount = GetCallStackFrames(scratch.a3);
    FormatCallStack(&callstackText, frameCount, scratch.a4);
    Logf("%s", callstackText.raw_data_unsafe());

    if (callstackText.myRes >= 0x10 && callstackText.bx.ptr) {
      ::operator delete(callstackText.bx.ptr);
    }
  }

  if (mCurCommandSource != kInvalidCommandSource) {
    const int cheaterSource = static_cast<int>(mCurCommandSource);
    const auto it = std::find(mCheaters.begin(), mCheaters.end(), cheaterSource);
    if (it == mCheaters.end()) {
      mCheaters.push_back(cheaterSource);
    }
  }

  mContext.Update(&mCheatsEnabled, 1u);
  return mCheatsEnabled;
}

/**
 * Address: 0x00747320 (FUN_00747320, ?OkayToMessWith@Sim@Moho@@QAE_NPAVSimArmy@2@@Z)
 *
 * What it does:
 * Validates whether current command source may issue actions on one army, with
 * cheat fallback when source authorization fails.
 */
bool Sim::OkayToMessWith(SimArmy* army)
{
  auto* armyImpl = static_cast<CArmyImpl*>(army);
  if (!armyImpl) {
    return CheatsEnabled();
  }

  if (armyImpl->IsOutOfGame) {
    return false;
  }

  const uint32_t sourceId = static_cast<uint32_t>(mCurCommandSource);
  if (sourceId != kInvalidCommandSource && armyImpl->MohoSetValidCommandSources.Contains(sourceId)) {
    return true;
  }

  return CheatsEnabled();
}

/**
 * Address: 0x00747360 (FUN_00747360, ?OkayToMessWith@Sim@Moho@@QAE_NPAVEntity@2@@Z)
 *
 * What it does:
 * Resolves entity owner army and delegates permission checks to army-level policy.
 */
bool Sim::OkayToMessWith(Entity* entity)
{
  return OkayToMessWith(entity ? static_cast<SimArmy*>(entity->ArmyRef) : nullptr);
}

/**
 * Address: 0x007473B0 (FUN_007473B0, ?OkayToMessWith@Sim@Moho@@QAE_NPAVCUnitCommand@2@@Z)
 *
 * What it does:
 * Checks each command unit-set entry against command-source permissions and
 * requires cheats for unusable or unauthorized entries.
 */
bool Sim::OkayToMessWith(CUnitCommand* cmd)
{
  if (!cmd) {
    return false;
  }

  CScriptObject** unitSetIt = cmd->mUnitSet.mVec.begin();
  CScriptObject** unitSetEnd = cmd->mUnitSet.mVec.end();
  if (unitSetIt == unitSetEnd) {
    return true;
  }

  while (unitSetIt != unitSetEnd) {
    CScriptObject* scriptObject = *unitSetIt;
    if (!SCommandUnitSet::IsUsableEntry(scriptObject)) {
      if (!CheatsEnabled()) {
        return false;
      }
      ++unitSetIt;
      continue;
    }

    Entity* entity = static_cast<Entity*>(scriptObject);
    if (!OkayToMessWith(entity)) {
      return false;
    }

    ++unitSetIt;
  }

  return true;
}

/**
 * Address: 0x00748650 (FUN_00748650, ?SetCommandSource@Sim@Moho@@UAEXI@Z)
 */
void Sim::SetCommandSource(const CommandSourceId sourceId)
{
  if (sourceId == kInvalidCommandSource || sourceId < static_cast<CommandSourceId>(mCommandSources.size())) {
    mCurCommandSource = static_cast<int32_t>(sourceId);
    return;
  }

  gpg::Warnf("Sim::SetCommandSource(%d): invalid source -- ignoring following commands.", sourceId);
  mCurCommandSource = static_cast<int32_t>(kInvalidCommandSource);
}

/**
 * Address: 0x007486B0 (FUN_007486B0, ?OnCommandSourceTerminated@Sim@Moho@@UAEXXZ)
 */
void Sim::OnCommandSourceTerminated()
{
  Logf("Command source %s terminated tick %d\n", GetCurrentCommandSourceName(), mCurTick);
  mContext.Update(&mCurCommandSource, 4u);
  mContext.Update(&mCurTick, 4u);

  if (mPausedByCommandSource == mCurCommandSource) {
    Resume();
  }

  for (std::size_t i = 0; i < mArmiesList.size(); ++i) {
    CArmyImpl* army = mArmiesList[i];
    if (!army) {
      continue;
    }

    if (!army->MohoSetValidCommandSources.Contains(static_cast<uint32_t>(mCurCommandSource))) {
      continue;
    }

    army->OnCommandSourceTerminated(static_cast<uint32_t>(mCurCommandSource));
  }
}

/**
 * Address: 0x00743120 (FUN_00743120, Moho::SDesyncInfo::SDesyncInfo)
 *
 * What it does:
 * Initializes one desync entry from beat/army metadata and both checksum
 * digest payloads.
 */
SDesyncInfo::SDesyncInfo(const std::int32_t beatValue, const std::int32_t armyValue, const gpg::MD5Digest& expectedHash, const gpg::MD5Digest& remoteHash)
  : beat(beatValue)
  , army(armyValue)
  , hash1(expectedHash)
  , hash2(remoteHash)
{}

/**
 * Address: 0x007487C0 (FUN_007487C0, ?VerifyChecksum@Sim@Moho@@UAEXABVMD5Digest@gpg@@H@Z)
 *
 * What it does:
 * Validates one remote beat checksum against the local rolling hash ring,
 * records a desync entry on mismatch, and clears the cached desync log list.
 */
void Sim::VerifyChecksum(const gpg::MD5Digest& checksum, const CSeqNo beat)
{
  if (mCurCommandSource == kInvalidCommandSource) {
    return;
  }

  const int oldestBeat = static_cast<int>(mCurBeat) - 128;
  if (beat < oldestBeat) {
    Logf(
      "Ignoring verify of beat %d because that was %d beats ago and we only have data for %d beats.",
      beat,
      static_cast<int>(mCurBeat) - beat,
      128
    );
    return;
  }

  if (beat >= static_cast<int>(mCurBeat)) {
    Logf("Ignoring verify of beat %d because it is in the future.", beat);
    return;
  }

  gpg::MD5Digest* expected = &mSimHashes[beat & 0x7F];
  if (std::memcmp(expected, &checksum, sizeof(gpg::MD5Digest)) == 0) {
    return;
  }

  const SDesyncInfo desync(beat, mCurCommandSource, *expected, checksum);
  mDesyncs.push_back(desync);

  const msvc8::string incomingHash = checksum.ToString();
  const msvc8::string simHash = expected->ToString();

  gpg::Warnf(
    "Checksum for beat %d mismatched: %s (sim) != %s (%s).",
    beat,
    simHash.c_str(),
    incomingHash.c_str(),
    GetCurrentCommandSourceName()
  );

  mIsDesyncFree = false;
  mDesyncLogLines.clear();
}

/**
 * Address: 0x00748600 (FUN_00748600, ?GetBeatChecksum@Sim@Moho@@QBE_NVCSeqNo@2@AAUMD5Digest@gpg@@@Z)
 *
 * What it does:
 * Copies one retained beat checksum out of the 128-entry rolling ring when
 * the requested beat is still available.
 */
bool Sim::GetBeatChecksum(gpg::MD5Digest* const outChecksum, const CSeqNo beat) const
{
  const int delta = static_cast<int>(beat) - static_cast<int>(mCurBeat);
  if (delta + 128 < 0 || delta >= 0) {
    return false;
  }

  *outChecksum = mSimHashes[static_cast<std::uint32_t>(beat) & 0x7Fu];
  return true;
}

/**
 * Address: 0x00748960 (FUN_00748960, ?RequestPause@Sim@Moho@@UAEXXZ)
 */
void Sim::RequestPause()
{
  if (mPausedByCommandSource != -1) {
    return;
  }

  if (mCurCommandSource == kInvalidCommandSource ||
      static_cast<std::size_t>(mCurCommandSource) >= mCommandSources.size()) {
    return;
  }

  int& timeouts = mCommandSources[mCurCommandSource].mTimeouts;
  if (timeouts <= 0) {
    return;
  }

  --timeouts;
  mPausedByCommandSource = mCurCommandSource;
}

/**
 * Address: 0x007489A0 (FUN_007489A0, ?Resume@Sim@Moho@@UAEXXZ)
 */
void Sim::Resume()
{
  if (mCurCommandSource != kInvalidCommandSource) {
    mPausedByCommandSource = -1;
  }
}

/**
 * Address: 0x007489C0 (FUN_007489C0, ?SingleStep@Sim@Moho@@UAEXXZ)
 */
void Sim::SingleStep()
{
  if (mPausedByCommandSource != -1 && mCurCommandSource != kInvalidCommandSource) {
    mSingleStep = true;
  }
}

/**
 * Address: 0x007491C0 (FUN_007491C0, ?ValidateNewCommandId@Sim@Moho@@AAE_NVCmdId@2@PBD@Z)
 *
 * CmdId, const char*
 *
 * What it does:
 * Validates one incoming command id against active command source byte and
 * rejects already-allocated command ids in the command DB map.
 *
 * Real disassembly calls `std::map_uint_CUnitCommand::find` (`sub_6E1940`,
 * cited on `rb_tree::find_node` in `RbTree.h`) directly against
 * `mCommandDB->mCommands` and rejects only when the found node is real and
 * its value is non-null (`a1 == head || !a1->_Myval.cmd` -> allow). It does
 * not null-check `mCommandDB` or the map head first -- both guards were a
 * `CCommandDbRuntimeView` reach-in artifact; `mCommandDB->commands` is
 * `CCommandDb`'s own real typed member (`CCommandDb.h`) and is always valid
 * once `Sim` is constructed.
 */
bool Sim::ValidateNewCommandId(const CmdId cmdId, const char* callsiteName) const
{
  const char* callsite = callsiteName ? callsiteName : "Sim";

  if (mCurCommandSource == kInvalidCommandSource) {
    gpg::Warnf("%s: ignoring issue of cmd id 0x%08x because there is no command source active.", callsite, cmdId);
    return false;
  }

  const uint32_t sourceByte = static_cast<uint32_t>(static_cast<uint8_t>(cmdId >> 24));
  const uint32_t currentSource = static_cast<uint32_t>(mCurCommandSource);
  if (sourceByte != currentSource) {
    gpg::Warnf(
      "%s: ignoring issue of cmd id 0x%08x from %s because the id's source (%u) is wrong (should be %u)",
      callsite,
      cmdId,
      GetCurrentCommandSourceName(),
      sourceByte,
      currentSource
    );
    return false;
  }

  const auto existingIt = mCommandDB->commands.find(cmdId);
  if (existingIt == mCommandDB->commands.end() || existingIt->second == nullptr) {
    return true;
  }

  gpg::Warnf(
    "%s: ignoring issue of cmd id 0x%08x from %s because it is already in use.",
    callsite,
    cmdId,
    GetCurrentCommandSourceName()
  );
  return false;
}

/**
 * Address: 0x007489E0 (FUN_007489E0)
 *
 * Moho::SUnitConstructionParams const &, bool
 *
 * IDA signature:
 * Moho::Unit *__userpurge Moho::Sim::CreateUnit@<eax>(Moho::SUnitConstructionParams *params@<esi>, char doCallback);
 *
 * What it does:
 * Applies army unit-cap checks and creates a Unit when caps allow.
 */
Unit* Sim::CreateUnit(const SUnitConstructionParams& params, const bool doCallback)
{
  if (!params.mArmy || !params.mBlueprint) {
    return nullptr;
  }

  if (!params.mArmy->IgnoreUnitCap()) {
    const float unitCap = params.mArmy->GetUnitCap();
    if (params.mArmy->GetArmyUnitCostTotal() + params.mBlueprint->General.CapCost > unitCap) {
      if (doCallback) {
        if (CAiBrain* const brain = params.mArmy->GetArmyBrain()) {
          reinterpret_cast<CScriptObject*>(brain)->CallbackStr("OnUnitCapLimitReached");
        }
      }
      return nullptr;
    }
  }

  return new Unit(params);
}

Unit* Sim::CreateUnitForScript(const SUnitConstructionParams& params, const bool doCallback)
{
  return CreateUnit(params, doCallback);
}

/**
 * Address: 0x007468E0 (FUN_007468E0, ?TransferUnit@Sim@Moho@@QAEPAVUnit@2@PAV32@PAVSimArmy@2@@Z)
 * Mangled: ?TransferUnit@Sim@Moho@@QAEPAVUnit@2@PAV32@PAVSimArmy@2@@Z
 *
 * IDA signature:
 * Moho::Unit *__thiscall Moho::Sim::TransferUnit(Moho::Sim *this, Moho::Unit *unit, Moho::CArmyImpl *newArmy);
 *
 * What it does:
 * Recursively transfers `unit` (plus its transport-carried cargo and attached
 * child units) to `newArmy`. Drains the transport storage, detaches child units
 * (splicing each child's `TransportedByRef` weak link out of its chain),
 * recursively transfers cargo and children, constructs a replacement Unit owned
 * by `newArmy`, migrates pose / health / custom name, re-populates transport
 * storage, re-attaches the transferred children, then destroys the original.
 * Returns the replacement Unit, or nullptr when the source is dead/destroy-queued
 * or the new army is over its unit cap.
 */
Unit* Sim::TransferUnit(Unit* const unit, CArmyImpl* const newArmy)
{
  if (!unit || unit->IsDead() || unit->DestroyQueued()) {
    return nullptr;
  }

  // Cargo transferred out of this unit's transport storage (parallel to
  // transferredCargo below), and the children transferred after detach.
  msvc8::vector<Unit*> transferredCargo;    // v57 (result of recursive transfer of stored units)
  msvc8::vector<Unit*> transferredChildren; // v56 (result of recursive transfer of attached units)
  msvc8::vector<Unit*> detachedChildren;    // v63 (mobile attached units, pre-detach)
  msvc8::vector<int> childParentBones;      // v65 (each child's mParentBoneIndex, captured pre-detach)
  msvc8::vector<int> childChildBones;       // v64 (each child's mChildBoneIndex, captured pre-detach)

  // --- Phase A: drain transport storage and recursively transfer the cargo ---
  if (IAiTransport* const transport = unit->AiTransport) {
    msvc8::vector<Unit*> storedCargo; // a2a

    EntitySetTemplate<Unit> storedUnits = transport->TransportGetStoredUnits();
    for (Unit* const storedUnit : storedUnits) {
      VTransform storedTransform{};
      storedTransform.orient_.w = 1.0f; // scratch out-transform (identity), receives the removed pose
      storedTransform.orient_.x = 0.0f;
      storedTransform.orient_.y = 0.0f;
      storedTransform.orient_.z = 0.0f;
      storedTransform.pos_.x = 0.0f;
      storedTransform.pos_.y = 0.0f;
      storedTransform.pos_.z = 0.0f;
      unit->AiTransport->TransportRemoveFromStorage(storedUnit, storedTransform);
      storedCargo.push_back(storedUnit);
    }

    for (Unit* const storedUnit : storedCargo) {
      Unit* const transferred = TransferUnit(storedUnit, newArmy);
      transferredCargo.push_back(transferred);
    }
  }

  // --- Phase B: capture mobile attached child units and their attach bones ---
  const msvc8::vector<Entity*>& attached = unit->GetAttachedEntities();
  for (Entity* const attachedEntity : attached) {
    if (!attachedEntity) {
      continue;
    }
    Unit* const child = attachedEntity->IsUnit();
    if (!child || !attachedEntity->IsMobile() || attachedEntity->Dead || attachedEntity->DestroyQueuedFlag) {
      continue;
    }
    detachedChildren.push_back(attachedEntity->IsUnit());
    childChildBones.push_back(attachedEntity->mAttachInfo.mChildBoneIndex);
    childParentBones.push_back(attachedEntity->mAttachInfo.mParentBoneIndex);
  }

  // --- Phase C: detach each captured child and unlink its transport weak-ref ---
  for (Unit* const child : detachedChildren) {
    child->DetachFrom(unit, true);
    child->TransportedByRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
  }

  // --- Phase D: recursively transfer the detached children ---
  for (Unit* const child : detachedChildren) {
    Unit* const transferred = TransferUnit(child, newArmy);
    transferredChildren.push_back(transferred);
  }

  // --- Phase F: construct the replacement unit under the new army ---
  const ELayer sourceLayer = unit->mCurrentLayer;
  const VTransform sourceTransform = unit->GetTransform();
  const RUnitBlueprint* const sourceBlueprint = unit->GetBlueprint();

  SUnitConstructionParams params(
    static_cast<std::int32_t>(sourceLayer),
    sourceTransform,
    newArmy,
    sourceBlueprint,
    nullptr,
    true
  );
  // The transfer path forces fixed-elevation on unconditionally (the layer==0 gate
  // that the shared ctor applies is not present in the shipped transfer code).
  params.mFixElevation = 1;

  Unit* const newUnit = CreateUnit(params, false);
  if (!newUnit) {
    // --- Phase H: creation failed (unit cap) — notify the army's brain script ---
    if (!newArmy->IgnoreUnitCap()) {
      if (CAiBrain* const brain = newArmy->GetArmyBrain()) {
        reinterpret_cast<CScriptObject*>(brain)->RunScript("OnFailedUnitTransfer");
      }
    }
    return nullptr;
  }

  // --- Phase G: migrate pose, health, and custom name onto the replacement ---
  newUnit->SetPoses(unit->AniActor->GetPriorPoseShared(), unit->AniActor->GetPoseShared());

  if (unit->Health != newUnit->Health) {
    newUnit->SetHealth(unit->Health);
  }

  newUnit->SetCustomName(unit->GetCustomName());

  // --- Phase G (transport): re-populate storage and re-attach children ---
  if (newUnit->AiTransport) {
    for (Unit* const cargo : transferredCargo) {
      if (cargo) {
        newUnit->AiTransport->TransportAddToStorage(cargo);
      }
    }

    const std::size_t childCount = transferredChildren.size();
    for (std::size_t i = 0; i < childCount; ++i) {
      Unit* const child = transferredChildren[i];
      if (!child) {
        continue;
      }

      const int parentBoneIndex = childParentBones[i];
      const int childBoneIndex = childChildBones[i];

      // Re-attach the transferred child to the replacement unit. The attach payload
      // reuses the captured bone indices with an identity relative transform
      // (scalar-first quaternion: w-lane = 1, all else 0).
      SEntAttachInfo attachInfo{};
      attachInfo.mAttachTargetWeak.BindObjectUnlinked(newUnit);
      (void)attachInfo.mAttachTargetWeak.LinkIntoOwnerChainHeadUnlinked();
      attachInfo.mParentBoneIndex = parentBoneIndex;
      attachInfo.mChildBoneIndex = childBoneIndex;
      attachInfo.mRelativeOrientX = 1.0f;
      attachInfo.mRelativeOrientY = 0.0f;
      attachInfo.mRelativeOrientZ = 0.0f;
      attachInfo.mRelativeOrientW = 0.0f;
      attachInfo.mRelativePosX = 0.0f;
      attachInfo.mRelativePosY = 0.0f;
      attachInfo.mRelativePosZ = 0.0f;

      child->AttachTo(attachInfo);
      // Detach the temporary attach node from the replacement's weak chain; the
      // durable linkage now lives in the child's own mAttachInfo.
      attachInfo.mAttachTargetWeak.UnlinkFromOwnerChain();

      newUnit->AiTransport->TransportAssignSlot(child, parentBoneIndex);

      if (newUnit->AiTransport) {
        // Resolve the attach bone's name and fire the child's OnTransportAttach
        // script, matching the transport attach path.
        const boost::shared_ptr<const CAniSkel> skeleton = newUnit->AniActor->GetSkeleton();
        const CAniSkel* const skel = skeleton.get();
        const char* boneName = nullptr;
        if (skel) {
          const SAniSkelBone* const bones = skel->mBones.begin();
          const std::size_t boneCount = static_cast<std::size_t>(skel->mBones.end() - bones);
          if (bones && static_cast<std::size_t>(parentBoneIndex) < boneCount) {
            boneName = bones[static_cast<std::size_t>(parentBoneIndex)].mBoneName;
          }
        }
        if (boneName) {
          newUnit->RunScriptStringUnit("OnTransportAttach", boneName, child);
        }
      }
    }
  }

  // --- Phase G (finalize): clear source footprint occupancy for static units ---
  if (!newUnit->IsMobile()) {
    unit->FootprintDown = false;
  }

  unit->Destroy();
  return newUnit;
}

/**
 * Address: 0x00748AA0 (FUN_00748AA0)
 *
 * unsigned int, Moho::RResId const &, Moho::SCoordsVec2 const &, float
 *
 * What it does:
 * Cheat-gated unit creation entrypoint; resolves unit blueprint, builds construction params,
 * and forwards into Sim::CreateUnit(const SUnitConstructionParams&, bool).
 */
void Sim::CreateUnit(const uint32_t armyIndex, const RResId& blueprintId, const SCoordsVec2& pos, const float heading)
{
  if (!CheatsEnabled()) {
    return;
  }

  if (armyIndex >= mArmiesList.size()) {
    return;
  }

  CArmyImpl* const army = mArmiesList[armyIndex];
  if (!army || army->IsOutOfGame) {
    return;
  }

  const RUnitBlueprint* const blueprint = ResolveUnitBlueprint(mRules, blueprintId);
  if (!blueprint) {
    Logf(
      "CreateUnit: unresolved blueprint '%s' requested by %s.\n",
      blueprintId.name.c_str(),
      GetCurrentCommandSourceName()
    );
    return;
  }

  SUnitConstructionParams params(
    0,
    BuildUnitSpawnTransform(pos, heading),
    army,
    blueprint,
    nullptr,
    true
  );
  params.mUseLayerOverride = 0;
  params.mFixElevation = 0;
  params.mLayer = 0;
  params.mComplete = 1;

  (void)CreateUnit(params, true);
}

/**
  * Alias of FUN_00748C00 (non-canonical helper lane).
 *
 * What it does:
 * Cheat-gated prop creation entry point for sim commands.
 */
void Sim::CreateProp(const char* blueprint, const Wm3::Vec3f& loc)
{
  if (!CheatsEnabled()) {
    return;
  }

  SpawnPropByBlueprint(this, mRules, blueprint, loc);
}

/**
 * Address: 0x00748C80 (FUN_00748C80)
 *
 * What it does:
 * Looks up an entity by id, validates command-source ownership, then
 * destroys the entity through `Entity::Destroy()`.
 */
void Sim::DestroyEntity(const EntId entityId)
{
  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity)) {
    return;
  }

  entity->Destroy();
}

/**
 * Address: 0x00748CD0 (FUN_00748CD0, ?WarpEntity@Sim@Moho@@UAEXVEntId@2@ABVVTransform@2@@Z)
 */
void Sim::WarpEntity(const EntId entityId, const VTransform& transform)
{
  if (!CheatsEnabled()) {
    return;
  }

  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity) {
    return;
  }

  ApplyWarpTransform(entity, transform);
}

/**
 * Address: 0x00748D50 (FUN_00748D50, ?ProcessInfoPair@Sim@Moho@@UAEXVEntId@2@VStrArg@gpg@@1@Z)
 *
 * What it does:
 * Applies one UI/info key-value command lane to a controllable live unit.
 */
void Sim::ProcessInfoPair(void* id, const char* key, const char* val)
{
  const EntId entityId = static_cast<EntId>(reinterpret_cast<std::uintptr_t>(id));
  Entity* const entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity) || entity->Dead != 0u) {
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetFireState")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    EFireState fireState = static_cast<EFireState>(0);
    gpg::RRef fireStateRef{};
    (void)gpg::RRef_EFireState(&fireStateRef, &fireState);
    (void)fireStateRef.SetLexical(val);
    if (static_cast<std::uint32_t>(fireState) <= 2u) {
      unit->SetFireState(static_cast<int>(fireState));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoMode")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetAutoMode(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoSurfaceMode")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetAutoSurfaceMode(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetRepeatQueue")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetRepeatQueue(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetPaused")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetPaused(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildTactical")) {
    Unit* const unit = entity->IsUnit();
    if (unit && gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 0);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildNuke")) {
    Unit* const unit = entity->IsUnit();
    if (unit && gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 1);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "CustomName")) {
    Unit* const unit = entity->IsUnit();
    if (unit) {
      unit->SetCustomName(std::string(val ? val : ""));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "ToggleScriptBit")) {
    Unit* const unit = entity->IsUnit();
    if (unit) {
      unit->ToggleScriptBit(std::atoi(val));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayNoStagingPlatformsVO")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)reinterpret_cast<CScriptObject*>(unit->ArmyRef->GetArmyBrain())->RunScript("OnPlayNoStagingPlatformsVO");
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayBusyStagingPlatformsVO")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)reinterpret_cast<CScriptObject*>(unit->ArmyRef->GetArmyBrain())->RunScript("OnPlayBusyStagingPlatformsVO");
    return;
  }
}

/**
 * Address: 0x00749290 (FUN_00749290)
 *
 * What it does:
 * Validates command-id ownership, filters selected units through sim command
 * access rules, and forwards the recovered shared-command dispatch to unit
 * queues.
 */
void Sim::IssueCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueCommand")) {
    return;
  }

  SEntitySetTemplateUnit selectedUnits{};

  auto collectUnit = [this, &selectedUnits](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)selectedUnits.AddUnit(unit);
  };

  entities.ForEachValue([&collectUnit](const unsigned int value) {
    collectUnit(static_cast<EntId>(value));
  });

  if (selectedUnits.Empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  if (commandIssueData.mCommandType == EUnitCommandType::UNITCOMMAND_DestroySelf && !CheatsEnabled()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  (void)IssueCommandToSelectedUnits(this, selectedUnits, commandIssueData, clearQueue);
}

/**
 * Address: 0x007494B0 (FUN_007494B0)
 *
 * What it does:
 * Validates command-id ownership, gathers controllable factory units, and
 * issues one shared factory command to every eligible builder.
 */
void Sim::IssueFactoryCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueFactoryCommand")) {
    return;
  }

  SEntitySetTemplateUnit selectedFactories{};
  auto collectFactory = [this, &selectedFactories](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)selectedFactories.AddUnit(unit);
  };

  entities.ForEachValue([&collectFactory](const unsigned int value) {
    collectFactory(static_cast<EntId>(value));
  });

  if (selectedFactories.Empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  (void)IssueFactoryCommandToSelectedUnits(this, selectedFactories, commandIssueData, clearQueue);
}

/**
 * Address: 0x00749680 (FUN_00749680, ?IncreaseCommandCount@Sim@Moho@@UAEXVCmdId@2@H@Z)
 */
void Sim::IncreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->IncreaseCount(count);
  }
}

/**
 * Address: 0x007496E0 (FUN_007496E0, ?DecreaseCommandCount@Sim@Moho@@UAEXVCmdId@2@H@Z)
 */
void Sim::DecreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->DecreaseCount(count);
  }
}

/**
 * Address: 0x00749740 (FUN_00749740, ?SetCommandTarget@Sim@Moho@@UAEXVCmdId@2@ABUSSTITarget@2@@Z)
 */
void Sim::SetCommandTarget(const CmdId cmdId, const SSTITarget& target)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  CAiTarget aiTarget{};
  aiTarget.DecodeFromSSTITarget(target, this);
  command->SetTarget(aiTarget);
}

/**
 * Address: 0x00749800 (FUN_00749800, ?SetCommandType@Sim@Moho@@UAEXVCmdId@2@W4EUnitCommandType@2@@Z)
 */
void Sim::SetCommandType(const CmdId cmdId, const EUnitCommandType commandType)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mCmdType = commandType;
  command->mNeedsUpdate = true;
}

/**
 * Address: 0x00749860 (FUN_00749860, ?SetCommandCells@Sim@Moho@@UAEXVCmdId@2@ABV?$fastvector@USOCellPos@Moho@@@gpg@@ABV?$Vector3@M@Wm3@@@Z)
 */
void Sim::SetCommandCells(
  const CmdId cmdId, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& targetPosition
)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mCells.clear();
  command->mVarDat.mCells.reserve(cells.Size());
  for (std::size_t i = 0; i < cells.Size(); ++i) {
    command->mVarDat.mCells.push_back(cells[i]);
  }
  command->mNeedsUpdate = true;

  CAiTarget aiTarget{};
  aiTarget.targetType = EAiTargetType::AITARGET_Ground;
  aiTarget.position = targetPosition;
  aiTarget.targetPoint = -1;
  aiTarget.targetIsMobile = false;
  command->SetTarget(aiTarget);
}

/**
 * Address: 0x00749970 (FUN_00749970, ?RemoveCommandFromUnitQueue@Sim@Moho@@UAEXVCmdId@2@VEntId@2@@Z)
 */
void Sim::RemoveCommandFromUnitQueue(const CmdId cmdId, const EntId unitId)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  Entity* matchedEntity = nullptr;
  for (CScriptObject** it = command->mUnitSet.mVec.begin(); it != command->mUnitSet.mVec.end(); ++it) {
    CScriptObject* scriptObject = *it;
    if (!SCommandUnitSet::IsUsableEntry(scriptObject)) {
      continue;
    }

    Entity* entity = static_cast<Entity*>(scriptObject);
    if (entity->id_ == unitId) {
      matchedEntity = entity;
      break;
    }
  }

  if (!matchedEntity || !OkayToMessWith(matchedEntity)) {
    return;
  }

  Unit* unit = matchedEntity->IsUnit();
  if (!unit || unit->IsDead()) {
    return;
  }

  CUnitCommandQueue* commandQueue = unit->CommandQueue;
  if (commandQueue && commandQueue->FindCommandIndex(command->mConstDat.cmd) != -1) {
    commandQueue->RemoveCommandFromQueue(command);
    return;
  }

  IAiBuilder* const builder = unit->AiBuilder;
  if (!builder) {
    return;
  }

  if (builder->BuilderContainsCommand(command)) {
    builder->BuilderRemoveFactoryCommand(command);
  }
}

/**
 * Address: 0x00749A70 (FUN_00749A70)
 *
 * char const *, LuaPlus::LuaObject const &
 *
 * IDA signature:
 * void __thiscall Moho::Sim::ExecuteLuaInSim(
 *   Moho::Sim *this,
 *   char const *functionName,
 *   LuaPlus::LuaObject const &args);
 *
 * What it does:
 * Cheat-gated Lua bridge that resolves a global function by name, pushes one
 * argument table/object payload, executes it with protected call, and restores
 * the Lua stack top.
 */
void Sim::ExecuteLuaInSim(const char* functionName, const LuaPlus::LuaObject& args)
{
  if (!CheatsEnabled() || !functionName || !mLuaState || !mLuaState->m_state) {
    return;
  }

  lua_State* state = mLuaState->m_state;
  const int oldTop = lua_gettop(state);

  lua_getglobal(state, functionName);
  if (!lua_isfunction(state, -1)) {
    lua_settop(state, oldTop);
    return;
  }

  try {
    LuaPlus::LuaPush(state, args);
  } catch (const std::exception&) {
    lua_pushnil(state);
  }

  if (lua_call(state, 1, 0) != 0) {
    const char* err = lua_tostring(state, -1);
    gpg::Warnf("Sim::ExecuteLuaInSim('%s') failed: %s", functionName, err ? err : "<unknown>");
  }

  lua_settop(state, oldTop);
}

namespace
{
  struct EntIdSetCursorLane
  {
    std::uint32_t reservedZero; // +0x00
    moho::BVIntSet* set;        // +0x04
    std::int32_t value;         // +0x08
  };
  static_assert(sizeof(EntIdSetCursorLane) == 0x0C, "EntIdSetCursorLane size must be 0x0C");
  static_assert(offsetof(EntIdSetCursorLane, set) == 0x04, "EntIdSetCursorLane::set offset must be 0x04");
  static_assert(offsetof(EntIdSetCursorLane, value) == 0x08, "EntIdSetCursorLane::value offset must be 0x08");

  /**
   * Address: 0x006E7A00 (FUN_006E7A00, ent-id set end-cursor lane helper)
   *
   * What it does:
   * Writes one `{set, endValue}` iterator lane for an ent-id set, where
   * `endValue` is `(firstWordIndex + wordCount) * 32`.
   */
  [[maybe_unused]] [[nodiscard]] EntIdSetCursorLane* BuildEntIdSetEndCursorLane(
    EntIdSetCursorLane* const out,
    const moho::BVSet<moho::EntId, moho::EntIdUniverse>* const entitySet
  ) noexcept
  {
    moho::BVIntSet* const bits = const_cast<moho::BVIntSet*>(&entitySet->mBits);
    const std::uintptr_t beginAddress = reinterpret_cast<std::uintptr_t>(bits->mWords.start_);
    const std::uintptr_t endAddress = reinterpret_cast<std::uintptr_t>(bits->mWords.end_);
    const std::uint32_t wordCount = static_cast<std::uint32_t>((endAddress - beginAddress) >> 2u);
    const std::uint32_t endValue = (bits->mFirstWordIndex + wordCount) << 5u;

    out->set = bits;
    out->value = static_cast<std::int32_t>(endValue);
    return out;
  }

} // namespace

// Given moho:: linkage rather than internal: the shipped binary had this
// file-static beside its only caller, but our tree recovers that caller
// (ISSUE_FactoryCommand) into CWldSession.cpp, so an internal-linkage body
// here can never satisfy it - it was one of the /FORCE-swallowed LNK2019s.
namespace moho
{
  /**
   * Address: 0x008B00A0 (FUN_008B00A0, func_DecodeEntIdSet)
   *
   * IDA signature:
   * Moho::EntIdSet *__cdecl func_DecodeEntIdSet(Moho::EntIdSet *a1, gpg::fastvector_UserUnit *a2);
   *
   * What it does:
   * Builds an `EntIdSet` (BVSet<EntId,EntIdUniverse>) from a list of selected
   * user units: resets `out`'s bit-set to empty, then walks `units` and inserts
   * each unit's entity id into the set. Every entity id must share the same
   * high-nibble type (`id >> 28`) as the first unit; a mismatch is a fatal
   * `gpg::Die`, matching CDecoder::DecodeEntIdSet's wire-decode guard.
   */
  void func_DecodeEntIdSet(
    moho::BVSet<moho::EntId, moho::EntIdUniverse>& out, const gpg::fastvector<moho::UserUnit*>& units
  )
  {
    // out->mSet default-empty: mFirstWordIndex/reserved cleared, SBO words
    // self-referential and empty (asm 0x8B00D0..0x8B00E1).
    out.Bits() = moho::BVIntSet{};

    if (units.begin() == units.end()) {
      return;
    }

    // The engine reads the packed entity id straight from the UserEntity
    // sub-object at [unit+0x44] (mParams.mEntityId). UserUnit and its
    // UserEntity view share the same address (see UserUnit.cpp's file-static
    // ResolveUserEntityView), so a direct reinterpret_cast reproduces the load.
    const auto entityIdOf = [](const moho::UserUnit* const unit) noexcept -> std::uint32_t {
      return reinterpret_cast<const moho::UserEntity*>(unit)->mParams.mEntityId;
    };

    // The shared id type is taken from the first unit and compared against
    // every element (asm reloads v5 from v7 == first nibble each iteration).
    const std::uint32_t firstType = entityIdOf(units.front()) >> 28u;

    for (moho::UserUnit* const unit : units) {
      const std::uint32_t entityId = entityIdOf(unit);
      const std::uint32_t entityType = entityId >> 28u;
      if (firstType != entityType) {
        gpg::Die(
          "Attempt to construct EntIdSet with different types of IDs (%d and %d) in DecodeEntIdSet",
          firstType,
          entityType
        );
      }

      (void)out.Bits().Add(entityId);
    }
  }
} // namespace moho

/**
 * Address: 0x00749B60 (FUN_00749B60, ?LuaSimCallback@Sim@Moho@@UAEXPBDABVLuaObject@LuaPlus@@ABV?$BVSet@HUEntIdUniverse@Moho@@@2@@Z)
 *
 * What it does:
 * Imports `/lua/SimCallbacks.lua`, resolves `DoCallback`, builds an optional
 * selected-unit table, then executes `DoCallback(callbackName,args,units)`.
 */
void Sim::LuaSimCallback(
  const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  LuaPlus::LuaObject selectedUnits(mLuaState);
  if (entities.Bits().Count() != 0u) {
    selectedUnits.AssignNewTable(mLuaState, 0, 0);

    int luaIndex = 1;
    auto appendUnitLuaObject = [this, &selectedUnits, &luaIndex](const EntId entId) {
      Entity* const entity = FindEntityById(mEntityDB, entId);
      if (!entity) {
        return;
      }

      Unit* const unit = entity->IsUnit();
      if (!unit) {
        return;
      }

      selectedUnits.SetObject(luaIndex, unit->GetLuaObject());
      ++luaIndex;
    };

    entities.ForEachValue([&appendUnitLuaObject](const unsigned int value) {
      appendUnitLuaObject(static_cast<EntId>(value));
    });
  }

  lua_State* const state = mLuaState->m_state;
  const int oldTop = lua_gettop(state);
  LuaPlus::LuaObject simCallbacksModule = SCR_Import(mLuaState, "/lua/SimCallbacks.lua");
  LuaPlus::LuaObject doCallbackObject = simCallbacksModule["DoCallback"];
  if (!doCallbackObject.IsFunction()) {
    doCallbackObject.TypeError("call");
  }

  const LuaPlus::LuaFunction<> doCallback(doCallbackObject);
  doCallback(callbackName, args, selectedUnits);
  lua_settop(state, oldTop);
}

/**
 * Address: 0x0070A4C0 (FUN_0070A4C0, Moho::Sim::SetArmyColor)
 *
 * IDA signature:
 * int __cdecl Moho::Sim::SetArmyColor(
 *   Moho::Sim* sim,
 *   std::vector<std::string>* commandArgs,
 *   Wm3::Vector3<float>* worldPos,
 *   Moho::CArmyImpl* focusArmy,
 *   Moho::SEntitySetTemplateUnit* selectedUnits);
 *
 * What it does:
 * Parses and applies the `SetArmyColor` sim-console command.
 */
int Sim::SetArmyColor(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !commandArgs || commandArgs->size() < 5u) {
    if (sim) {
      sim->Printf(kSetArmyColorSyntaxText);
    }
    return 0;
  }

  const int armyIndex = std::atoi((*commandArgs)[1].c_str());
  const int red = std::atoi((*commandArgs)[2].c_str());
  const int green = std::atoi((*commandArgs)[3].c_str());
  const int blue = std::atoi((*commandArgs)[4].c_str());
  const std::uint32_t packedColor = PackOpaqueArmyColor(red, green, blue);

  if (armyIndex < 0 || static_cast<std::size_t>(armyIndex) >= sim->mArmiesList.size()) {
    sim->Printf(kSetArmyColorInvalidArmyText, armyIndex);
    return 0;
  }

  CArmyImpl* const army = sim->mArmiesList[static_cast<std::size_t>(armyIndex)];
  if (!army) {
    sim->Printf(kSetArmyColorInvalidArmyText, armyIndex);
    return 0;
  }

  army->PlayerColorBgra = packedColor;
  army->ArmyColorBgra = packedColor;
  return 0;
}

/**
 * Address: 0x0064BD20 (FUN_0064BD20, Moho::Sim::DamageUnit)
 *
 * IDA signature:
 * void callcnv_33 Moho::Sim::DamageUnit(Moho::Sim *a1, std::vector_string *a4,
 *     Wm3::Vector3f *a3, Moho::CArmyImpl *_B0, std::vector_WeakObject_IUnit *a5);
 *
 * What it does:
 * `DamageUnit <amount>` console command - see the declaration. The binary
 * open-codes both weak-pointer operations as owner-chain walks: the instigator
 * detach at 0x0064BDE6..0x0064BDFD and the per-unit target rebind at
 * 0x0064BE60..0x0064BEA9. Both are exactly `WeakPtr<T>::Set`, so they are
 * expressed through it rather than re-spelled here.
 */
int Sim::DamageUnit(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (commandArgs == nullptr || commandArgs->size() < 2u) {
    sim->Printf(kDamageUnitUsageText);
    return 0;
  }

  CDamage damage(sim);
  damage.mMethod = CDamage_SINGLE_TARGET;
  damage.mAmount = static_cast<float>(std::atof(commandArgs->at(1).c_str()));

  // 0x0064BDE6: the instigator the CDamage constructor installed is unlinked
  // again, so debug damage is attributed to nobody.
  damage.mInstigator.Set(nullptr);

  // 0x0064BE01..0x0064BE36: the shared zero vector at 0x00F3D21C.
  damage.mVector = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  damage.mType = kDamageUnitDamageType;
  damage.mDamageFriendly = 1u;

  if (selectedUnits == nullptr) {
    return 0;
  }

  for (Entity* const entity : selectedUnits->mVec) {
    damage.mTarget.Set(entity);
    SIM_Damage(sim, damage);
  }

  return 0;
}

/**
 * Address: 0x00651B00 (FUN_00651B00, Moho::Sim::dbg)
 *
 * What it does:
 * Toggles one debug overlay by name, or prints available overlays and
 * prefix-match diagnostics when selection is omitted/ambiguous.
 */
int Sim::dbg(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  if (commandArgs == nullptr || commandArgs->empty()) {
    PrintAvailableDebugOverlayList(*sim);
    return 0;
  }

  if (commandArgs->size() > 2u) {
    sim->Printf(kDbgUsageText, commandArgs->front().c_str());
    return 0;
  }

  if (commandArgs->size() < 2u) {
    PrintAvailableDebugOverlayList(*sim);
    return 0;
  }

  const std::string& requestedOverlayName = commandArgs->at(1);

  gpg::RType* selectedType = TryFindExactDebugOverlayType(requestedOverlayName);
  if (selectedType == nullptr) {
    std::vector<const RDebugOverlayClass*> prefixMatches;
    CollectPrefixDebugOverlayTypes(requestedOverlayName, prefixMatches);

    if (prefixMatches.empty()) {
      sim->Printf(kDbgUnknownOverlayText, requestedOverlayName.c_str());
      PrintAvailableDebugOverlayList(*sim);
      return 0;
    }

    if (prefixMatches.size() > 1u) {
      sim->Printf(kDbgAmbiguousOverlayText, requestedOverlayName.c_str());
      sim->Printf(kDbgCouldBeAnyOfText);
      for (const RDebugOverlayClass* const overlayClass : prefixMatches) {
        if (overlayClass == nullptr) {
          continue;
        }
        sim->Printf("  %s - %s", overlayClass->GetName(), overlayClass->mOverlayDescription.c_str());
      }
      return 0;
    }

    selectedType = const_cast<RDebugOverlayClass*>(prefixMatches.front());
  }

  if (selectedType == nullptr) {
    return 0;
  }

  if (RDebugOverlay* const existingOverlay = FindDebugOverlayInstanceByType(*sim, *selectedType);
      existingOverlay != nullptr) {
    RemoveDebugOverlayInstance(*existingOverlay);
    return 0;
  }

  if (RDebugOverlay* const newOverlay = CreateDebugOverlayInstance(*selectedType); newOverlay != nullptr) {
    LinkDebugOverlayFront(*sim, *newOverlay);
  }

  return 0;
}

/**
 * Address: 0x006D17B0 (FUN_006D17B0, Moho::Sim::DebugSetConsumptionActive)
 *
 * What it does:
 * Enables upkeep consumption for each currently selected unit.
 */
int Sim::DebugSetConsumptionActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.SetConsumptionActive(true);
  });
  return 0;
}

/**
 * Address: 0x006D17F0 (FUN_006D17F0, Moho::Sim::DebugSetConsumptionInActive)
 *
 * What it does:
 * Disables upkeep consumption for each currently selected unit.
 */
int Sim::DebugSetConsumptionInActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.SetConsumptionActive(false);
  });
  return 0;
}

/**
 * Address: 0x006D1830 (FUN_006D1830, Moho::Sim::DebugSetProductionActive)
 *
 * What it does:
 * Marks selected units as production-active and dispatches
 * `OnProductionActive`.
 */
int Sim::DebugSetProductionActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.ProductionActive = true;
    unit.RunScript("OnProductionActive");
  });
  return 0;
}

/**
 * Address: 0x006D1880 (FUN_006D1880, Moho::Sim::DebugSetProductionInActive)
 *
 * What it does:
 * Marks selected units as production-inactive and dispatches
 * `OnProductionInActive`.
 */
int Sim::DebugSetProductionInActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.ProductionActive = false;
    unit.RunScript("OnProductionInActive");
  });
  return 0;
}

/**
 * Address: 0x006D18D0 (FUN_006D18D0, Moho::Sim::DebugAIStatesOn)
 *
 * What it does:
 * Enables per-unit AI debug-state display for currently selected units.
 */
int Sim::DebugAIStatesOn(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.mDebugAIStates = true;
  });
  return 0;
}

/**
 * Address: 0x006D1900 (FUN_006D1900, Moho::Sim::DebugAIStatesOff)
 *
 * What it does:
 * Disables per-unit AI debug-state display for currently selected units and
 * clears published AI debug stats.
 */
int Sim::DebugAIStatesOff(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.mDebugAIStates = false;
    unit.ShowAIDebugInfo(false);
  });
  return 0;
}

/**
 * Address: 0x0075ED00 (FUN_0075ED00, Moho::Sim::TrackStats)
 *
 * What it does:
 * Parses `TrackStats <true|false|reset>` and either toggles selected-unit
 * tracking for the focus army or clears `RealTimeStats` for all armies.
 */
int Sim::TrackStats(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 2) {
    const char* const commandName =
      (commandArgs != nullptr && !commandArgs->empty()) ? commandArgs->front().c_str() : "TrackStats";
    if (sim != nullptr) {
      sim->Printf("usage: %s <true|false|reset>", commandName);
    }
    return 0;
  }

  const std::string& mode = (*commandArgs)[1];
  if (mode != "reset") {
    const bool enableTracking = (mode == "true");
    ForEachSelectedUnit(selectedUnits, [focusArmy, enableTracking](Unit& unit) {
      if (unit.ArmyRef != focusArmy) {
        return;
      }

      auto* const trackStatsView = reinterpret_cast<UnitTrackStatsRuntimeView*>(&unit);
      trackStatsView->trackingEnabled = enableTracking;
    });
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (army == nullptr) {
      continue;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats != nullptr) {
      armyStats->Delete("RealTimeStats");
    }
  }

  return 0;
}

namespace
{
  struct DumpUnitsCountEntry
  {
    const RUnitBlueprint* blueprint = nullptr;
    int count = 0;
  };

  static_assert(sizeof(DumpUnitsCountEntry) == 8, "DumpUnitsCountEntry size must be 8");
  static_assert(std::is_trivially_copyable_v<DumpUnitsCountEntry>,
                "DumpUnitsCountEntry must be trivially copyable for the msvc8 _Insert_n memmove lane");

  /**
   * Address: 0x0075FDB0 (FUN_0075FDB0)
   *
   * What it does:
   * Sorts one contiguous `DumpUnitsCountEntry` range by descending population
   * count using the binary lane's non-stable ordering contract.
   *
   * The binary's hand-rolled introsort variant recursively invokes the MSVC8
   * `_Adjust_heap` sift-down lane on this element type -- see
   * `Address: 0x00760590 (FUN_00760590` on the `DumpUnitsCountEntry`
   * instantiation cited in `legacy/algorithms/Sort.h`'s `adjust_heap`
   * template. `std::sort` in modern C++20 encapsulates the same heapify +
   * partition + insertion-sort machinery with identical worst-case order,
   * so the explicit heapify helper disappears at the intent-first source
   * level while preserving binary-equivalent ordering for finite inputs.
   */
  void SortDumpUnitsCountEntries(
    DumpUnitsCountEntry* const begin,
    DumpUnitsCountEntry* const end,
    const std::int32_t depthLimit,
    const std::int32_t userContext
  )
  {
    (void)depthLimit;
    (void)userContext;
    if (begin == nullptr || end == nullptr || begin >= end) {
      return;
    }

    std::sort(begin, end, [](const DumpUnitsCountEntry& lhs, const DumpUnitsCountEntry& rhs) {
      return lhs.count > rhs.count;
    });
  }
} // namespace

/**
 * Address: 0x0075EE50 (FUN_0075EE50, Moho::Sim::DumpUnits)
 *
 * What it does:
 * Aggregates live units by blueprint owner pointer, sorts by descending
 * population, and logs one `"<blueprintId> <count>"` line per entry.
 */
int Sim::DumpUnits(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr || sim->mEntityDB == nullptr) {
    return 0;
  }

  // ABI: msvc8::vector so counts.push_back(...) names the MSVC8 STL grow lane
  // vector<DumpUnitsCountEntry>::_Insert_n (FUN_0075F810) on the capacity-full
  // path, matching the original binary; std::vector would inline its own grow.
  msvc8::vector<DumpUnitsCountEntry> counts;
  CEntityDb* const entityDb = sim->mEntityDB;
  CEntityDbAllUnitsNode* node = entityDb->AllUnitsEnd(0u);
  CEntityDbAllUnitsNode* const end = entityDb->AllUnitsEnd();
  while (node != end) {
    Unit* const unit = CEntityDb::UnitFromAllUnitsNode(node);
    node = CEntityDb::NextAllUnitsNode(node);
    if (unit == nullptr) {
      continue;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    auto found = std::find_if(counts.begin(), counts.end(), [blueprint](const DumpUnitsCountEntry& entry) {
      return entry.blueprint == blueprint;
    });
    if (found == counts.end()) {
      counts.push_back(DumpUnitsCountEntry{blueprint, 1});
    } else {
      ++found->count;
    }
  }

  if (!counts.empty()) {
    DumpUnitsCountEntry* const begin = counts.data();
    DumpUnitsCountEntry* const finish = begin + counts.size();
    const auto depthLimit = static_cast<std::int32_t>(counts.size());
    SortDumpUnitsCountEntries(begin, finish, depthLimit, 0);
  }

  for (const DumpUnitsCountEntry& entry : counts) {
    if (entry.blueprint == nullptr) {
      continue;
    }

    gpg::Logf("%s %i", entry.blueprint->mBlueprintId.c_str(), entry.count);
  }

  return 0;
}

/**
 * Address: 0x0075D7A0 (FUN_0075D7A0, Moho::Sim::DebugDumpArmyStats)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DebugDumpArmyStats(
 *     Moho::Sim *sim, std::vector_string *commandArgs, Wm3::Vector3f *worldPos,
 *     Moho::CArmyImpl *focusArmy, std::vector_WeakObject_IUnit *selectedUnits);
 *
 * What it does:
 * `DebugDumpArmyStats <armyIndex>` console callback. With fewer than two
 * tokens it prints the usage line; otherwise it parses the index, looks that
 * army up in `mArmiesList` (`[edx+910h]`/`[edx+914h]` at 0x0075D7F5 and
 * 0x0075D802) and, when the slot holds a live army, dumps its stat snapshot
 * through `CArmyStats::DumpStats` (0x0075D838).
 *
 * The binary indexes `mArmiesList` twice - once to load the army pointer at
 * 0x0075D814 and once for the `GetArmyStats` call at 0x0075D82E - so the
 * inlined bounds check appears twice, and the failing arm at 0x0075D840 is
 * the usual null-deref trap. Only the first index can actually fail, so the
 * recovered form keeps the single guard the source expressed.
 */
int Sim::DebugDumpArmyStats(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr || commandArgs->size() < 2u) {
    sim->Printf("usage: DebugDumpArmyStats armyIndex");
    return 0;
  }

  const auto armyIndex = static_cast<std::size_t>(std::atoi((*commandArgs)[1].c_str()));
  if (armyIndex >= sim->mArmiesList.size()) {
    return 0;
  }

  if (CArmyImpl* const army = sim->mArmiesList[armyIndex]; army != nullptr) {
    army->GetArmyStats()->DumpStats();
  }

  return 0;
}

/**
 * Address: 0x0064BB80 (FUN_0064BB80, Moho::Sim::SallyShears)
 *
 * What it does:
 * Toggles fog-of-war state across every army recon database.
 */
int Sim::SallyShears(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (army == nullptr) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb == nullptr) {
      continue;
    }

    reconDb->ReconSetFogOfWar(!reconDb->ReconGetFogOfWar());
  }

  return 0;
}

namespace
{
  constexpr std::uint64_t kInt64SignBitMask = 0x8000000000000000ull;
  constexpr std::uint64_t kInt64MagnitudeMask = 0x7FFFFFFFFFFFFFFFull;
  constexpr double kSignedInt64HighBitContribution = -9223372036854775808.0;

  [[nodiscard]] float ConvertSignedStorageLaneToFloat(const std::uint64_t lane) noexcept
  {
    double value = static_cast<double>(lane & kInt64MagnitudeMask);
    if ((lane & kInt64SignBitMask) != 0ull) {
      value += kSignedInt64HighBitContribution;
    }
    return static_cast<float>(value);
  }

  /**
   * Address: 0x0064BA60 (FUN_0064BA60)
   *
   * What it does:
   * Converts `SEconTotals::mMaxStorage` signed 64-bit ENERGY/MASS lanes into a
   * pair of float lanes using the original sign-bit split conversion path.
   */
  [[nodiscard]] SEconPair* BuildSignedMaxStorageFloatPair(
    SEconPair* const outPair,
    const SEconTotals& totals
  ) noexcept
  {
    outPair->ENERGY = ConvertSignedStorageLaneToFloat(totals.mMaxStorage.ENERGY);
    outPair->MASS = ConvertSignedStorageLaneToFloat(totals.mMaxStorage.MASS);
    return outPair;
  }
} // namespace

/**
 * Address: 0x0064BBE0 (FUN_0064BBE0, Moho::Sim::BlingBling)
 *
 * What it does:
 * Increases focus-army extra storage by 10000 energy/mass and credits current
 * resources by the updated max-storage lanes.
 */
int Sim::BlingBling(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)selectedUnits;

  if (focusArmy == nullptr) {
    if (sim != nullptr) {
      sim->Printf("No focus army.");
    }
    return 0;
  }

  CSimArmyEconomyInfo* const economyInfo = focusArmy->GetEconomy();
  CEconStorageRuntimeView* const storage = GetArmyEconStorage(*focusArmy);
  if (economyInfo == nullptr || storage == nullptr) {
    return 0;
  }

  ApplyEconStorageDelta(*storage, -1);
  storage->amounts[0] += 10000.0f;
  storage->amounts[1] += 10000.0f;
  ApplyEconStorageDelta(*storage, 1);

  SEconPair grantedStorage{};
  (void)BuildSignedMaxStorageFloatPair(&grantedStorage, economyInfo->economy);
  economyInfo->economy.mStored.ENERGY += grantedStorage.ENERGY;
  economyInfo->economy.mStored.MASS += grantedStorage.MASS;
  focusArmy->EnergyCurrent = economyInfo->economy.mStored.ENERGY;
  focusArmy->MassCurrent = economyInfo->economy.mStored.MASS;

  return 0;
}

/**
 * Address: 0x0064BCA0 (FUN_0064BCA0, Moho::Sim::ZeroExtraStorage)
 *
 * What it does:
 * Zeroes focus-army extra-storage lanes after removing and reapplying storage
 * delta contribution.
 */
int Sim::ZeroExtraStorage(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)selectedUnits;

  if (focusArmy == nullptr) {
    if (sim != nullptr) {
      sim->Printf("No focus army.");
    }
    return 0;
  }

  CEconStorageRuntimeView* const storage = GetArmyEconStorage(*focusArmy);
  if (storage == nullptr) {
    return 0;
  }

  ApplyEconStorageDelta(*storage, -1);
  storage->amounts[0] = 0.0f;
  storage->amounts[1] = 0.0f;
  ApplyEconStorageDelta(*storage, 1);
  return 0;
}

/**
 * Address: 0x0064BF00 (FUN_0064BF00, Moho::Sim::AddImpulse)
 *
 * What it does:
 * Parses three impulse components, applies the impulse to each selected
 * unit's motion controller, and forces each selected unit into `LAYER_Air`.
 */
int Sim::AddImpulse(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 4u) {
    if (sim != nullptr) {
      const int got = commandArgs != nullptr ? static_cast<int>(commandArgs->size()) : 0;
      sim->Printf("Insufficient args: got %i, expected %i", got, 4);
    }
    return 0;
  }

  const Wm3::Vector3f impulse{
    static_cast<float>(std::atof(commandArgs->at(1).c_str())),
    static_cast<float>(std::atof(commandArgs->at(2).c_str())),
    static_cast<float>(std::atof(commandArgs->at(3).c_str()))
  };

  ForEachSelectedUnit(selectedUnits, [&impulse](Unit& unit) {
    if (unit.UnitMotion != nullptr) {
      unit.UnitMotion->AddRecoilImpulse(impulse);
    }
    unit.SetCurrentLayer(LAYER_Air);
  });

  return 0;
}

/**
 * Address: 0x005C37B0 (FUN_005C37B0, Moho::Sim::ReconFlush)
 *
 * What it does:
 * Flushes every army recon database currently attached to this sim.
 */
int Sim::ReconFlush(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim) {
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (!army) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb) {
      reconDb->Flush();
    }
  }

  return 0;
}

/**
 * Address: 0x00684D00 (FUN_00684D00, Moho::Sim::Purge)
 *
 * What it does:
 * Purges entities by category token and optional army filter.
 */
int Sim::Purge(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !sim->mEntityDB || !commandArgs || commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& categoryToken = commandArgs->at(1);
  const PurgeCategory category = ParsePurgeCategory(categoryToken);
  if (category == PurgeCategory::Unknown) {
    sim->Printf("Unknown type %s", categoryToken.c_str());
    return 0;
  }

  int armyFilter = -1;
  if (commandArgs->size() > 2u) {
    armyFilter = std::atoi(commandArgs->at(2).c_str());
  }

  std::vector<Entity*> targets;
  const msvc8::list<Entity*>& entities = sim->mEntityDB->Entities();
  for (Entity* const entity : entities) {
    if (!entity) {
      continue;
    }

    if (!EntityMatchesPurgeCategory(*entity, category)) {
      continue;
    }

    if (!EntityMatchesPurgeArmyFilter(*entity, armyFilter)) {
      continue;
    }

    if (!ShouldDestroyEntityForPurge(*entity)) {
      continue;
    }

    targets.push_back(entity);
  }

  for (Entity* const entity : targets) {
    if (entity) {
      entity->Destroy();
    }
  }

  return 0;
}

/**
 * Address: 0x006B6B40 (FUN_006B6B40, Moho::Sim::KillAll)
 *
 * What it does:
 * Kills every unit in the requested armies, or every army when no army
 * indexes are supplied.
 */
int Sim::KillAll(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  ForEachTargetArmyUnit(sim, commandArgs, [](Unit& unit) {
    unit.Kill(nullptr, "", 0.0f);
  });
  return 0;
}

/**
 * Address: 0x006B6DC0 (FUN_006B6DC0, Moho::Sim::DestroyAll)
 *
 * What it does:
 * Destroys every unit in the requested armies, or every army when no army
 * indexes are supplied.
 */
int Sim::DestroyAll(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  ForEachTargetArmyUnit(sim, commandArgs, [](Unit& unit) {
    static_cast<Entity&>(unit).Destroy();
  });
  return 0;
}

/**
 * Address: 0x006540A0 (FUN_006540A0)
 *
 * What it does:
 * Returns the effect-manager pointer lane stored on one `Sim` runtime object.
 */
[[nodiscard]] CEffectManagerImpl* ReadEffectManagerLane(const Sim* const sim)
{
  return sim->mEffectManager;
}

/**
 * Address: 0x0065E9D0 (FUN_0065E9D0, Moho::Sim::efx_NewEmitter)
 *
 * What it does:
 * Creates one emitter at the cursor world position when a blueprint name is
 * provided.
 */
int Sim::efx_NewEmitter(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos) || !commandArgs) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  if (commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& blueprintName = commandArgs->at(1);
  effectManager->CreateEmitter(*worldPos, blueprintName.c_str(), -1);
  return 0;
}

/**
 * Address: 0x0065EA50 (FUN_0065EA50, Moho::Sim::efx_AttachEmitter)
 *
 * What it does:
 * Uses command arg #1 as the target bone name and command args #2..N as
 * emitter blueprint tokens, then attaches each emitter token to each selected
 * unit when the primary emitter blueprint resolves in rules.
 */
int Sim::efx_AttachEmitter(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (!sim || !sim->mRules || !commandArgs || !selectedUnits) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  if (commandArgs->size() < 3u) {
    return 0;
  }

  const std::string& boneName = commandArgs->at(1);
  const std::string& primaryEmitterBlueprint = commandArgs->at(2);

  RResId emitterId{};
  gpg::STR_InitFilename(&emitterId.name, primaryEmitterBlueprint.c_str());
  if (sim->mRules->GetEmitterBlueprint(emitterId) == nullptr) {
    return 0;
  }

  ForEachSelectedUnit(selectedUnits, [&](Unit& unit) {
    Entity* const entity = static_cast<Entity*>(&unit);
    for (std::size_t index = 2u; index < commandArgs->size(); ++index) {
      const std::string& emitterBlueprint = commandArgs->at(index);
      const int boneIndex = entity->ResolveBoneIndex(boneName.c_str());
      effectManager->CreateAttachedEmitter(entity, boneIndex, emitterBlueprint.c_str(), -1);
    }
  });

  return 0;
}

/**
 * Address: 0x0066BD90 (FUN_0066BD90, func_AddLightParticle_SimConFunc)
 *
 * What it does:
 * Parses optional `lifetime`, `size`, and `texture` args, then creates a light
 * particle using `ramp_white_01` as the secondary texture.
 */
int Sim::AddLightParticle(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos)) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  float lifetime = 2.0f;
  float size = 1.0f;
  msvc8::string texturePrimary{};

  if (commandArgs && commandArgs->size() > 1u) {
    for (std::size_t i = 1u; i < commandArgs->size(); ++i) {
      const std::string& key = commandArgs->at(i);
      const std::string* value = (i + 1u < commandArgs->size()) ? &commandArgs->at(i + 1u) : nullptr;
      if (!value) {
        continue;
      }

      if (key == "lifetime") {
        lifetime = static_cast<float>(std::atof(value->c_str()));
      } else if (key == "size") {
        size = static_cast<float>(std::atof(value->c_str()));
      } else if (key == "texture") {
        texturePrimary.assign_owned(value->c_str());
      }
    }
  }

  const msvc8::string textureSecondary("ramp_white_01");
  effectManager->CreateLightParticle(*worldPos, texturePrimary, textureSecondary, size, lifetime, -1);
  return 0;
}

/**
 * Address: 0x00734F50 (FUN_00734F50, Moho::Sim::Log)
 *
 * What it does:
 * Joins command args #1..N with spaces and logs the resulting text via
 * `gpg::Logf("%s", ...)`.
 */
int Sim::Log(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Logf("%s", joined.c_str());
  return 0;
}

/**
 * Address: 0x00734FF0 (FUN_00734FF0, Moho::Sim::SimWarn)
 *
 * What it does:
 * Joins command args #1..N with spaces and warns using `gpg::Warnf("%s", ...)`.
 */
int Sim::SimWarn(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Warnf("%s", joined.c_str());
  return 0;
}

/**
 * Address: 0x00735090 (FUN_00735090, Moho::Sim::SimError)
 *
 * What it does:
 * Joins command args #1..N with spaces and terminates with
 * `gpg::Die("%s", ...)`. Returns `int` because it's invoked as a Lua C
 * function (which require an `int` return slot for the result count); the
 * function is in practice noreturn via `gpg::Die`/`std::abort` but the
 * `[[noreturn]]` attribute can't be applied to non-void return types
 * (C4646), so it is omitted here.
 */
int Sim::SimError(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Die("%s", joined.c_str());
  std::abort();
}

/**
 * Address: 0x00699D20 (FUN_00699D20, Moho::Sim::sim_Gravity)
 *
 * Moho::Sim *, std::vector<msvc8::string> *
 *
 * What it does:
 * Prints the current gravity value, or parses a new scalar and stores it as
 * the downward gravity acceleration on the active sim.
 */
int Sim::sim_Gravity(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->empty()) {
    if (sim != nullptr) {
      sim->Printf("usage: %s [new-value]", "sim_Gravity");
      sim->Printf("    where new-value is in ogrids/(second^2)");
    }
    return 0;
  }

  if (sim->mPhysConstants == nullptr) {
    return 0;
  }

  Wm3::Vector3f& gravity = sim->mPhysConstants->mGravity;
  if (commandArgs->size() == 1u) {
    sim->Printf("Gravity is %.2f ogrids/(second^2) down.", -gravity.y);
    return 0;
  }

  if (commandArgs->size() == 2u) {
    float newGravity = 0.0f;
    const std::string& argument = commandArgs->at(1);
    if (::sscanf_s(argument.c_str(), "%f", &newGravity) == 1) {
      gravity.y = -newGravity;
      sim->Printf("Changing gravity to %.2f ogrids/(second^2) down.", newGravity);
    } else {
      sim->Printf("Invalid number: %s", argument.c_str());
    }
    return 0;
  }

  sim->Printf("usage: %s [new-value]", commandArgs->front().c_str());
  sim->Printf("    where new-value is in ogrids/(second^2)");
  return 0;
}

/**
 * Address: 0x00735110 (FUN_00735110, Moho::Sim::SimAssert)
 *
 * What it does:
 * No-op debug command callback lane.
 */
int Sim::SimAssert(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;
  return 0;
}

/**
 * Address: 0x00735120 (FUN_00735120, Moho::Sim::SimCrash)
 *
 * What it does:
 * Triggers an intentional null-write crash for debug fault testing.
 */
int Sim::SimCrash(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
  return 0;
}

/**
 * Address: 0x0074B610 (FUN_0074B610, Moho::Sim::sim_DebugCrash)
 *
 * What it does:
 * Triggers an intentional null-write crash for debug fault testing.
 */
int Sim::sim_DebugCrash(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
  return 0;
}

/**
 * Address: 0x00734BA0 (FUN_00734BA0, Moho::Sim::sim_TestFunc)
 *
 * What it does:
 * Debug console-command stub for the `sim_TestFunc` test entry: prints this
 * sim instance's own address and returns.
 */
int Sim::sim_TestFunc(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  sim->Printf("sim=0x%08x", sim);
  return 0;
}

/**
 * Address: 0x0074B3F0 (FUN_0074B3F0, Moho::Sim::ScenarioMethod)
 *
 * What it does:
 * Looks up one scenario callback in `ScenarioInfo.Env` using command arg #1
 * and invokes it if present; warns when the callback is undefined.
 */
int Sim::ScenarioMethod(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr) {
    return 0;
  }

  const int argumentCount = static_cast<int>(commandArgs->size());
  if (argumentCount < 2 || sim == nullptr || sim->mLuaState == nullptr) {
    return argumentCount;
  }

  const std::string& methodName = commandArgs->at(1);
  LuaPlus::LuaObject globals = sim->mLuaState->GetGlobals();
  LuaPlus::LuaObject scenarioInfoObject = globals["ScenarioInfo"];
  LuaPlus::LuaObject scenarioEnvObject = scenarioInfoObject["Env"];
  LuaPlus::LuaObject scenarioMethodObject = scenarioEnvObject[methodName.c_str()];

  if (scenarioMethodObject) {
    LuaPlus::LuaFunction scenarioMethodFunction(scenarioMethodObject);
    scenarioMethodFunction.Call();
  } else {
    gpg::Warnf("ScenarioMethod '%s' not defined", methodName.c_str());
  }

  return 0;
}

/**
 * Address: 0x007595C0 (FUN_007595C0, Moho::Sim::SimLua)
 *
 * What it does:
 * Builds one Lua expression from sim-command args #1..N, exposes the first
 * selected unit as global `__selected_unit`, executes the expression, then
 * clears `__selected_unit`.
 */
int Sim::SimLua(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 2u || sim->mLuaState == nullptr) {
    return 0;
  }

  auto clearSelectedUnitGlobal = [sim]() {
    lua_State* const rawState = sim->mLuaState != nullptr ? sim->mLuaState->GetCState() : nullptr;
    if (rawState == nullptr) {
      return;
    }

    lua_pushnil(rawState);
    lua_setglobal(rawState, "__selected_unit");
  };

  LuaPlus::LuaObject globals = sim->mLuaState->GetGlobals();
  Unit* selectedUnit = nullptr;
  if (selectedUnits != nullptr && selectedUnits->mVec.begin() != selectedUnits->mVec.end()) {
    selectedUnit = SEntitySetTemplateUnit::UnitFromEntry(*selectedUnits->mVec.begin());
  }

  if (selectedUnit != nullptr) {
    LuaPlus::LuaObject selectedUnitObject = selectedUnit->GetLuaObject();
    globals.SetObject("__selected_unit", selectedUnitObject);
  } else {
    clearSelectedUnitGlobal();
  }

  std::string commandText = commandArgs->at(1);
  for (std::size_t argIndex = 2u; argIndex < commandArgs->size(); ++argIndex) {
    commandText.push_back(' ');
    commandText += commandArgs->at(argIndex);
  }

  sim->Printf("%s", commandText.c_str());
  (void)SCR_LuaDoString(commandText.c_str(), sim->mLuaState);
  clearSelectedUnitGlobal();
  return 0;
}

/**
 * Address: 0x0075D5D0 (FUN_0075D5D0, Moho::Sim::DebugSetPlayableRect)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DebugSetPlayableRect(Moho::Sim *sim, std::vector_string *commandArgs);
 *
 * What it does:
 * `DebugSetPlayableRect x0 y0 x1 y1`. Parses the four bounds with `atoi` into
 * a `gpg::Rect2i` laid out `{x0, z0, x1, z1}` (0x0075D6A6..0x0075D6C2 stores
 * arg1 -> x0, arg2 -> z0, arg3 -> x1, arg4 -> z1), asks the sim's `STIMap` to
 * clamp and adopt it, and on success mirrors the change into Sim Lua by
 * running `SyncPlayableRect({ ... })`. The Lua mirror is built from the *raw
 * argument tokens*, not from the clamped rectangle - 0x0075D6EF re-reads the
 * argument vector and pushes the four strings in the order
 * `x0=arg1, x1=arg3, y0=arg2, y1=arg4`.
 */
int Sim::DebugSetPlayableRect(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr || commandArgs->size() < 5u) {
    sim->Printf(kDebugSetPlayableRectUsageText);
    return 0;
  }

  const gpg::Rect2i playableRect{
    std::atoi(commandArgs->at(1u).c_str()),
    std::atoi(commandArgs->at(2u).c_str()),
    std::atoi(commandArgs->at(3u).c_str()),
    std::atoi(commandArgs->at(4u).c_str())
  };

  if (!sim->mMapData->SetPlayableMapRect(playableRect)) {
    sim->Printf(kDebugSetPlayableRectInvalidText);
    return 0;
  }

  const msvc8::string syncCommand = gpg::STR_Printf(
    kDebugSetPlayableRectSyncFormat,
    commandArgs->at(1u).c_str(),
    commandArgs->at(3u).c_str(),
    commandArgs->at(2u).c_str(),
    commandArgs->at(4u).c_str()
  );
  (void)SCR_LuaDoString(syncCommand.c_str(), sim->mLuaState);
  return 0;
}

/**
 * Address: 0x0075D860 (FUN_0075D860, Moho::Sim::DebugMoveCamera)
 *
 * What it does:
 * Builds and executes `DebugMoveCamera(x0,y0,x1,y1)` in Sim Lua from command
 * args #1..#4.
 */
int Sim::DebugMoveCamera(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  SEntitySetTemplateUnit* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  if (commandArgs == nullptr || commandArgs->size() < 5u) {
    sim->Printf("usage: DebugMoveCamera x0 y0 x1 y1");
    return 0;
  }

  const msvc8::string commandText = gpg::STR_Printf(
    "DebugMoveCamera(%s,%s,%s,%s)",
    commandArgs->at(1).c_str(),
    commandArgs->at(2).c_str(),
    commandArgs->at(3).c_str(),
    commandArgs->at(4).c_str()
  );
  (void)SCR_LuaDoString(commandText.c_str(), sim->mLuaState);
  return 0;
}

/**
 * Address: 0x00734870 (FUN_00734870, func_TryParseSimCommand)
 *
 * IDA signature:
 * void __cdecl func_TryParseSimCommand(
 *   Moho::Sim *sim,
 *   char *commandText,
 *   Wm3::Vector3<float> *worldPos,
 *   Moho::CArmyImpl *focusArmy,
 *   Moho::SEntitySetTemplateUnit *selectedUnits);
 *
 * What it does:
 * Parses one or more sim debug command segments, resolves each segment through
 * the global `simcons` registry, applies cheat gating, and dispatches through
 * CSimConCommand virtual handlers.
 */
void Sim::TryParseSimCommand(
  const char* command,
  const Wm3::Vector3<float>& worldPos,
  CArmyImpl* focusArmy,
  SEntitySetTemplateUnit& selectedUnits
)
{
  const char* const rawCommandText = command ? command : "";
  std::string remaining = rawCommandText;
  Wm3::Vector3<float>* const mutableWorldPos = const_cast<Wm3::Vector3<float>*>(&worldPos);

  while (!remaining.empty()) {
    std::vector<std::string> parsedCommand;
    std::string nextCommandChain;
    ParseOneSimCommand(remaining, parsedCommand, nextCommandChain);

    if (!parsedCommand.empty()) {
      CSimConCommand* const simCommand = FindSimConCommand(parsedCommand.front());
      if (!simCommand) {
        Logf("Unknown sim command '%s' [invoked by %s]\n", parsedCommand.front().c_str(), GetCurrentCommandSourceName());
      } else {
        const bool requiresCheat = simCommand->mRequiresCheat != 0;
        if (requiresCheat && !CheatsEnabled()) {
          return;
        }

        if (requiresCheat) {
          const std::string commandText = UnparseSimCommand(parsedCommand);
          Logf("%s: %s\n", GetCurrentCommandSourceName(), commandText.c_str());
        }

        try {
          (void)simCommand->Run(this, &parsedCommand, mutableWorldPos, focusArmy, &selectedUnits);
        } catch (const std::exception& ex) {
          const char* const errorText = ex.what() ? ex.what() : "<unknown>";
          gpg::Warnf("error running sim console command %s: %s", rawCommandText, errorText);

          if (!requiresCheat) {
            Logf("error running sim console command %s: %s\n", rawCommandText, errorText);
          }
        }
      }
    }

    remaining = nextCommandChain;
  }
}

/**
 * Address: 0x00749DA0 (FUN_00749DA0)
 *
 * What it does:
 * Collects selected units into a temporary entity-set payload and forwards the
 * parsed command line through the sim debug parser chain.
 */
void Sim::ExecuteDebugCommand(
  const char* command,
  const Wm3::Vector3<float>& worldPos,
  const uint32_t focusArmy,
  const BVSet<EntId, EntIdUniverse>& entities
)
{
  SEntitySetTemplateUnit selectedUnits{};
  InitSimDebugEntitySet(selectedUnits);

  auto appendSelectedUnit = [this, &selectedUnits](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    selectedUnits.AppendUniqueEntity(static_cast<Entity*>(unit));
  };

  entities.ForEachValue([&appendSelectedUnit](const unsigned int value) {
    appendSelectedUnit(static_cast<EntId>(value));
  });

  CArmyImpl* focusArmyPtr = nullptr;
  if (focusArmy < mArmiesList.size()) {
    focusArmyPtr = mArmiesList[focusArmy];
  }

  // 0x00734870 parser chain is now lifted in native C++ via TryParseSimCommand().
  TryParseSimCommand(command, worldPos, focusArmyPtr, selectedUnits);
  DestroySimDebugEntitySet(selectedUnits);
}

/**
 * Address: 0x00749F40 (FUN_00749F40)
 *
 * int
 *
 * IDA signature:
 * void __thiscall Moho::Sim::AdvanceBeat(Moho::Sim *this, int amt);
 *
 * What it does:
 * Advances one simulation beat: updates rules/lua hooks, ticks armies/tasks,
 * advances coord entities, drains deferred destroys, and runs periodic
 * checksum/GC maintenance.
 *
 * Recovery status:
 * Partial high-fidelity lift. Core beat staging is restored, with one
 * additional sync-filter packing pass still tracked for follow-up evidence.
 */
void Sim::AdvanceBeat(const int amt)
{
  (void)amt; // Binary implementation does not consume this parameter at 0x00749F40.

  Logf("********** beat %u **********\n", mCurBeat);
  RulesUpdateLuaState(mRules, mLuaState);

  if (IsDebugWindowEnabled() && mLuaState && mLuaState->m_state) {
    lua_sethook(mLuaState->m_state, GetDebugLuaHook(), 4, 0);
  }

  if (!mGameOver && (mPausedByCommandSource == -1 || mSingleStep)) {
    ++mCurTick;
    Logf("  tick number %u\n", mCurTick);

    if (ReadSimConVarBool(this, PathBackgroundUpdateConVar(), false)) {
      const int pathBudget = ReadSimConVarInt(this, PathBackgroundBudgetConVar(), 0);
      UpdatePaths(mPathTables, pathBudget);
    }

    ForEachAllArmyUnit(mEntityDB, [](Unit* unit) {
      if (!unit || unit->IsDead()) {
        return;
      }

      unit->ClearBeatResourceAccumulators();
    });

    for (CArmyImpl* army : mArmiesList) {
      if (army) {
        army->OnTick();
      }
    }

    TickTaskStage(&mTaskStageA);
    TickTaskStage(&mDiskWatcherTaskStage);
    TickTaskStage(&mTaskStageB);
    RefreshBlips();

    if (!mArmiesList.empty()) {
      const std::size_t armyCount = mArmiesList.size();
      const std::size_t reconTickIndex = static_cast<std::size_t>(mCurTick) % armyCount;
      for (std::size_t i = 0; i < armyCount; ++i) {
        CArmyImpl* army = mArmiesList[i];
        if (!army) {
          continue;
        }

        CAiReconDBImpl* reconDb = army->GetReconDB();
        if (!reconDb) {
          continue;
        }

        if (i == reconTickIndex) {
          reconDb->ReconTick(static_cast<int>(armyCount));
        } else {
          reconDb->ReconRefresh();
        }
      }
    }

    TickEffectManager(mEffectManager);
    UpdateFormationDb(mFormationDB);

    ForEachAllArmyUnit(mEntityDB, [](Unit* unit) {
      if (unit->NeedsKillCleanup()) {
        unit->KillCleanup();
      }
    });

    for (auto* entity : mCoordEntities.owners_member<Entity, &Entity::mCoordNode>()) {
      AdvanceCoords(entity);
    }

    // Sync-filter extra-data packing pass. Every id in the outgoing sync
    // filter that still resolves to a live unit contributes one record.
    // `push_back(SExtraUnitData())` is `msvc8::vector<SExtraUnitData>::
    // push_back` (FUN_0074C160, Vector.h) -- the `.asm`-confirmed shape:
    // the record is copy-constructed in (default `pairs`, zero tag) and
    // then filled in place through the returned `back()` reference, so its
    // inline pair storage is anchored inside the vector element rather
    // than aliasing a temporary that could be relocated by a later grow.
    mSyncFilter.maskA.ForEachValue([this](const unsigned int entityId) {
      Entity* const entity = mEntityDB->FindEntityById(entityId);
      if (entity == nullptr) {
        return;
      }

      Unit* const unit = entity->IsUnit();
      if (unit == nullptr) {
        return;
      }

      mSyncSerializeGroup2.push_back(SExtraUnitData());
      SExtraUnitData& record = mSyncSerializeGroup2.back();
      record.unitEntityId = kUnsetExtraUnitDataOwnerId;
      unit->GetExtraData(&record);
    });

    mDebugCanvas2 = mDebugCanvas1;
    mDebugCanvas1.reset();

    mAdvancedThisTick = true;
    mSingleStep = false;
  }

  while (!mDeletionQueue.empty()) {
    void* queuedObject = mDeletionQueue.front();
    mDeletionQueue.pop_front();
    RunQueuedDestroy(queuedObject);
  }

  PurgeDestroyedEffects(mEffectManager);
  CleanupDecals(mDecalBuffer);

  const int checksumPeriod = ReadSimConVarInt(this, ChecksumPeriodConVar(), 1);
  if (checksumPeriod > 0 && (mCurBeat % static_cast<uint32_t>(checksumPeriod)) == 0u) {
    UpdateChecksum();
  }

  for (auto* node = mDebugOverlays.mPrev; node != &mDebugOverlays; node = node->mPrev) {
    auto* overlay = static_cast<RDebugOverlay*>(node);
    TickDebugOverlay(overlay, this);
  }

  if (mLuaState && mLuaState->m_state && (mCurTick % 70u) == 0u) {
    lua_setgcthreshold(mLuaState->m_state, 0);
  }

  // +0x08FC latch: set here in AdvanceBeat, cleared in Sim::Sync.
  mDidProcess = true;
}

/**
 * Address: 0x007457F0 (FUN_007457F0, ?Shutdown@Sim@Moho@@QAEXXZ)
 *
 * What it does:
 * Destroys live units, drains the deferred deletion queue, shuts down the
 * sim sound manager, and latches `mDidProcess`.
 */
void Sim::Shutdown()
{
  ForEachAllArmyUnit(mEntityDB, [](Unit* const unit) {
    if (unit != nullptr) {
      static_cast<Entity&>(*unit).Destroy();
    }
  });

  while (!mDeletionQueue.empty()) {
    void* const queuedObject = mDeletionQueue.front();
    mDeletionQueue.pop_front();
    RunQueuedDestroy(queuedObject);
  }

  if (mSoundManager != nullptr) {
    mSoundManager->Shutdown();
  }

  mDidProcess = true;
}

/**
 * Address: 0x0074AFB0 (FUN_0074AFB0, ?SaveState@Sim@Moho@@QAEXAAVWriteArchive@gpg@@@Z)
 *
 * What it does:
 * Checks NIS-state save gate through `/lua/cinematics.lua::IsOpEnded`,
 * then writes this `Sim` object to the supplied archive.
 */
void Sim::SaveState(gpg::WriteArchive* const archive)
{
  bool isNisMode = false;
  if (mLuaState) {
    LuaPlus::LuaObject cinematicsModule = SCR_ImportLuaModule(mLuaState, "/lua/cinematics.lua");
    LuaPlus::LuaObject isOpEndedFn = SCR_GetLuaTableField(mLuaState, cinematicsModule, "IsOpEnded");

    lua_State* const state = mLuaState->GetCState();
    if (state && !isOpEndedFn.IsNil()) {
      const int savedTop = lua_gettop(state);
      isOpEndedFn.PushStack(state);
      if (lua_isfunction(state, -1) && lua_call(state, 0, 1) == 0) {
        isNisMode = lua_toboolean(state, -1) != 0;
      }
      lua_settop(state, savedTop);
    }
  }

  if (isNisMode) {
    throw std::runtime_error("Attemped Save in NIS mode");
  }

  gpg::RRef ownerRef{};
  if (!Sim::sType) {
    Sim::sType = gpg::LookupRType(typeid(Sim));
  }

  archive->Write(Sim::sType, this, ownerRef);
  archive->EndSection(false);
}

/**
 * Address: 0x0074B100 (FUN_0074B100, ?EndGame@Sim@Moho@@UAEXXZ)
 *
 * What it does:
 * Marks the sim as ended.
 */
void Sim::EndGame()
{
  mGameEnded = true;
}

/**
 * Address: 0x005859B0 (FUN_005859B0, Moho::Sim::ArmyCount)
 *
 * What it does:
 * Returns the number of army slots in the sim army list.
 */
int Sim::ArmyCount() const
{
  return static_cast<int>(mArmiesList.size());
}

/**
 * Address: 0x0128B140 (FUN_0128B140, func_CallbackPacketRecv)
 *
 * What it does:
 * Emits the callback-packet patch diagnostics line.
 */
void moho::func_CallbackPacketRecv()
{
  gpg::Logf(kCallbackPacketMessage);
}

/**
 * Address: 0x0128B160 (FUN_0128B160, func_CheckDiscard)
 *
 * What it does:
 * Clears discard status, scans the patch client list for a pointer match,
 * and logs/marks discard when matched.
 */
void moho::func_CheckDiscard(const void* const clientPointer)
{
  gDiscardPatchState.didDiscard = 0;

  if (gDiscardPatchState.currentClientCount == 1u) {
    return;
  }

  const std::size_t scanCount = ResolveDiscardScanCount(gDiscardPatchState.currentClientCount);
  if (!ContainsPointer(gDiscardPatchState.clientPointers, scanCount, clientPointer)) {
    return;
  }

  gpg::Logf(kDiscardedPointerMessage, clientPointer);
  gDiscardPatchState.didDiscard = 1;
}

/**
 * Address: 0x0128B2C0 (FUN_0128B2C0, func_LogRecv)
 *
 * What it does:
 * Logs the received packet pointer.
 */
void moho::func_LogRecv(const void* const receivedPointer)
{
  gpg::Logf(kRecvPointerMessage, receivedPointer);
}

/**
 * Address: 0x008D4010 (FUN_008D4010, funcl_SC_CreateEntityDialog)
 *
 * What it does:
 * Thunk entry that routes SC create-entity dialog callback through patch gate.
 */
void moho::funcl_SC_CreateEntityDialog()
{
  patch_SC_CreateEntityDialog();
}

/**
 * Address: 0x0128BEF0 (FUN_0128BEF0, patch_SC_CreateEntityDialog)
 *
 * What it does:
 * Applies cheat-enable gate before opening create-entity debug dialog.
 */
void moho::patch_SC_CreateEntityDialog()
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session && session->IsCheatsEnabled) {
    func_original_SC_CreateEntityDialog();
  }
}

/**
 * Address: 0x0128BF00 (FUN_0128BF00, func_original_SC_CreateEntityDialog)
 *
 * What it does:
 * Calls original create-entity dialog body after patch gate passes.
 */
void moho::func_original_SC_CreateEntityDialog()
{
  func_SC_CreateEntityDialog_chunk();
}

/**
 * Address: 0x008D4016 (FUN_008D4016, func_SC_CreateEntityDialog_chunk)
 *
 * What it does:
 * Resolves first selected unit and opens blueprint edit dialog for that unit.
 */
void moho::func_SC_CreateEntityDialog_chunk()
{
  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return;
  }

  msvc8::vector<UserUnit*> selectedUnits{};
  session->GetSelectionUnits(selectedUnits);
  if (selectedUnits.empty()) {
    return;
  }

  UserUnit* const firstSelectedUnit = selectedUnits.front();
  IUnit* const iunitBridge = ResolveIUnitBridge(firstSelectedUnit);
  if (!iunitBridge) {
    return;
  }

  RUnitBlueprint const* const blueprint = iunitBridge->GetBlueprint();
  if (!blueprint) {
    return;
  }

  gpg::RRef blueprintRef(const_cast<RUnitBlueprint*>(blueprint), gpg::LookupRType(typeid(RUnitBlueprint)));
  REF_CreateEditDialog(blueprintRef, blueprint->mBlueprintId.c_str());
}

/**
 * Address: 0x00528550 (FUN_00528550, cfunc_SpecFootprintsL)
 *
 * What it does:
 * Loads one Lua table-array of footprint specs into the rules footprint list,
 * warning and skipping duplicate named entries.
 */
int moho::cfunc_SpecFootprintsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  RRuleGameRulesImpl* const rules = ResolveRulesImpl(state);
  if (!rules || !rules->mFootprints.mHead) {
    return 0;
  }

  gpg::ScopedLogContext footprintScope("Initializing footprint groups");

  SRuleFootprintsBlueprint& footprintTable = rules->mFootprints;
  lua_State* const rawState = state->m_state;
  const LuaPlus::LuaObject footprintSpecsObject(LuaPlus::LuaStackObject(state, 1));
  const int footprintSpecCount = footprintSpecsObject.GetCount();
  for (int luaIndex = 1; luaIndex <= footprintSpecCount; ++luaIndex) {
    SNamedFootprint footprint{};
    footprint.mIndex = static_cast<std::int32_t>(footprintTable.mSize);

    lua_rawgeti(rawState, 1, luaIndex);
    const LuaPlus::LuaObject footprintObject(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));

    const LuaPlus::LuaObject nameObject = footprintObject.GetByName("Name");
    const char* const nameText = nameObject.GetString();
    footprint.mName = nameText ? nameText : "";

    const LuaPlus::LuaObject sizeXObject = footprintObject.GetByName("SizeX");
    footprint.mSizeX = static_cast<std::uint8_t>(sizeXObject.GetInteger());

    const LuaPlus::LuaObject sizeZObject = footprintObject.GetByName("SizeZ");
    footprint.mSizeZ = static_cast<std::uint8_t>(sizeZObject.GetInteger());

    const LuaPlus::LuaObject capsObject = footprintObject.GetByName("Caps");
    footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(capsObject.GetInteger());

    const LuaPlus::LuaObject minWaterDepthObject = footprintObject.GetByName("MinWaterDepth");
    if (minWaterDepthObject) {
      footprint.mMinWaterDepth = static_cast<float>(minWaterDepthObject.GetNumber());
    }

    const LuaPlus::LuaObject maxWaterDepthObject = footprintObject.GetByName("MaxWaterDepth");
    if (maxWaterDepthObject) {
      footprint.mMaxWaterDepth = static_cast<float>(maxWaterDepthObject.GetNumber());
    }

    const LuaPlus::LuaObject maxSlopeObject = footprintObject.GetByName("MaxSlope");
    if (maxSlopeObject) {
      footprint.mMaxSlope = static_cast<float>(maxSlopeObject.GetNumber());
    }

    const LuaPlus::LuaObject flagsObject = footprintObject.GetByName("Flags");
    if (flagsObject) {
      footprint.mFlags = static_cast<EFootprintFlags>(flagsObject.GetInteger());
    }

    if (HasNamedFootprint(footprintTable, footprint.mName)) {
      gpg::Warnf("Ignoring duplicate footprint spec %s", footprint.mName.c_str());
      continue;
    }

    AppendNamedFootprint(footprintTable, footprint);
  }

  return 0;
}

/**
 * Address: 0x005284D0 (FUN_005284D0, cfunc_SpecFootprints)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_SpecFootprintsL`.
 */
int moho::cfunc_SpecFootprints(lua_State* const luaContext)
{
  return cfunc_SpecFootprintsL(moho::SCR_ResolveBindingState(luaContext));
}

namespace
{
  [[nodiscard]] moho::RRuleGameRulesImpl* ResolveLuaBlueprintRules(LuaPlus::LuaState* const state) noexcept
  {
    if (moho::RRuleGameRulesImpl* const rules = moho::BlueprintLoaderContext().mRules; rules != nullptr) {
      return rules;
    }
    return ResolveRulesImpl(state);
  }

  // Helper block for the blueprint registration chain.
  //
  // Every one of FUN_005289D0 (register category membership), FUN_00531D80
  // (unit blueprint create/find path), FUN_00532080 (prop blueprint
  // create/find path) and FUN_00532380 (projectile blueprint create/find
  // path) is a real, standalone binary function boundary with its own real
  // callers (confirmed via each token's `.xrefs.txt`), not compiler-emitted
  // glue or inlined-away logic. FUN_00531D80/FUN_00532080/FUN_00532380 are
  // recovered below as `CreateOrGet*BlueprintFromState` (see their own
  // `Address:` blocks). FUN_005289D0 is recovered immediately below as
  // `RegisterBlueprintCategoryMembership` (see its `Address:` block for the
  // full evidence trail); a prior pass here had incorrectly claimed none of
  // the four carried standalone boundaries and left FUN_005289D0's mapping
  // uncited -- that claim did not hold even for this block's own siblings
  // (`AddCategoryMemberBit`, `AppendBlueprintOrdinal` and
  // `RegisterBlueprintInCategoryMaps` below already cite their own
  // `FUN_005555C0`/`FUN_005347A0`/`FUN_00529B30` addresses).
  // CategoryLookupValue/CategoryLookupMap/EntityCategoryLookupTableView used
  // to be defined here as a second, per-TU-only copy of the exact same
  // binary object RRuleGameRules.cpp's `EntityCategoryLookupTableRuntimeView`
  // models (`RRuleGameRulesImpl::mEntityCategoryLookup`, +0xC4) -- this
  // anonymous namespace's version reached it read the same live object
  // through `ResolveEntityCategoryLookupTable`'s `reinterpret_cast` below.
  // Per the CLAUDE.md duplicate-layout contract ("pick a single owning
  // reconstructed definition"), that duplication is gone: the real type
  // (identical layout, identical evidence -- 8-byte-aligned node, value at
  // node+0x10, colour/isNil at node+0x58/0x59, all independently
  // re-verified against the raw decompiles during the RRuleGameRules.cpp
  // migration this promotion is part of) now lives once, in
  // `moho::CategoryLookupValue`/`moho::CategoryLookupMap`/
  // `moho::EntityCategoryLookupTableRuntimeView` (RRuleGameRules.h), and
  // this file uses that shared definition directly instead of a
  // `reinterpret_cast`-punned twin. `RbTree.h`'s `insert_unique`/`insert_at`/
  // `buy_node`/`rb_decrement`/`find_node` citations for this instantiation
  // (below, on `AddCategoryMemberBit`) are unaffected -- same type, same
  // addresses, just one definition instead of two.

  struct BlueprintNodeIdPayloadView
  {
    msvc8::string mBlueprintId; // +0x00
    void* mBlueprint;           // +0x1C
  };

  static_assert(sizeof(BlueprintNodeIdPayloadView) == 0x20, "BlueprintNodeIdPayloadView size must be 0x20");
  static_assert(
    offsetof(BlueprintNodeIdPayloadView, mBlueprintId) == 0x00,
    "BlueprintNodeIdPayloadView::mBlueprintId offset must be 0x00"
  );
  static_assert(
    offsetof(BlueprintNodeIdPayloadView, mBlueprint) == 0x1C,
    "BlueprintNodeIdPayloadView::mBlueprint offset must be 0x1C"
  );

  /**
   * Address: 0x005347A0 (FUN_005347A0, msvc8::vector<Moho::RBlueprint*>::push_back)
   *
   * IDA signature:
   * unsigned int __usercall sub_5347A0@<eax>(RBlueprint **value@<eax>,
   *                                          std::vector_RBlueprint_P *vec);
   *
   * What it does:
   * Appends one blueprint pointer to the by-ordinal registry at `rules + 0xB4`
   * (`add ecx, 0B4h` at 0x00531FE9 in `func_CreateRUnitBlueprint`). The append
   * is the legacy container's own `push_back`; on the capacity-full path MSVC8
   * routes it into the `vector<RBlueprint*>::insert(end(), 1, value)` lane
   * emitted at FUN_00535D60.
   *
   * The parameter stays `void*` because the recovered `REntityBlueprint`
   * models the shared blueprint header by layout duplication rather than by
   * deriving from `RBlueprint`, so `RUnitBlueprint*` has no implicit
   * conversion to the registry's element type yet. The binary stores the raw
   * pointer value either way.
   */
  void AppendBlueprintOrdinal(RRuleGameRulesImpl& rules, void* const blueprintObject)
  {
    if (blueprintObject == nullptr) {
      return;
    }

    // push_back's capacity-full path is `msvc8::vector<RBlueprint*>::insert`
    // (FUN_00535D60), reached through the binary's push_back at FUN_005347A0.
    rules.mBlueprintsByOrdinal.push_back(static_cast<RBlueprint*>(blueprintObject));
  }

  /**
   * Address: 0x00529B30 (FUN_00529B30, func_Add__blueprints) -- `mMaps` lane
   *
   * What it does:
   * Inserts the newly registered blueprint's ordinal into every currently
   * connected Lua export binding's pending-ordinal set
   * (`RRuleGameRulesImpl::mMaps[i].mPendingBlueprintOrdinals`), so
   * `RRuleGameRulesImpl::UpdateLuaState`'s next `SynchronizeBlueprintTable`
   * pass for that target state knows this blueprint needs to be (re-)pushed
   * -- `UpdateLuaState` clears the set right after synchronizing
   * (RRuleGameRules.cpp), matching a pending/dirty-set role.
   *
   * The binary performs this as the loop at 0x00529BE3-0x00529C0B, calling
   * `func_MapInsert` / `FUN_0052BC60` (`msvc8::detail::rb_tree<...>::
   * insert_unique` for the `msvc8::set<uint32_t>` embedded at
   * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` -- see the
   * citation block on `insert_unique` in RbTree.h) on `binding + 4` for
   * every existing `[mMaps.begin(), mMaps.end())` binding, using the
   * blueprint's `mBlueprintOrdinal` (+0x5C) as the key.
   *
   * `mMaps` is a real `msvc8::vector<RRuleGameRulesLuaExportBinding>`
   * (RRuleGameRules.h); this walk uses its own `begin()`/`end()` instead of
   * the hand-rolled `mBegin`/`mEnd` pointer fields the now-removed
   * `RRuleGameRulesLuaExportBindingArray` used to expose.
   */
  void RegisterBlueprintInCategoryMaps(RRuleGameRulesImpl& rules, void* const blueprintObject)
  {
    if (blueprintObject == nullptr) {
      return;
    }

    const auto* const blueprint = reinterpret_cast<const RBlueprint*>(blueprintObject);
    const auto ordinal = static_cast<std::uint32_t>(blueprint->mBlueprintOrdinal);

    for (RRuleGameRulesLuaExportBinding& binding : rules.mMaps) {
      (void)binding.mPendingBlueprintOrdinals.insert(ordinal);
    }
  }

  [[nodiscard]] EntityCategoryLookupTableRuntimeView* ResolveEntityCategoryLookupTable(RRuleGameRulesImpl& rules) noexcept
  {
    // `mEntityCategoryLookup` is already `EntityCategoryLookupTableRuntimeView*`
    // (RRuleGameRules.h) -- no cast needed now that this file shares that
    // type instead of reinterpret_casting its own separate duplicate.
    return rules.mEntityCategoryLookup;
  }

  /**
   * Address: 0x005555C0 (FUN_005555C0)
   *
   * IDA signature:
   * int __thiscall sub_5555C0(std::vector *this, std::string *a2,
   *                           Moho::RUnitBlueprint *arg4);
   *
   * What it does:
   * Looks the category name up in the entity-category lookup map
   * (`categoryMap.find`, 0x005561C0 -- `Address:` on `rb_tree::find_node`,
   * RbTree.h), inserts a fresh node when the lookup misses
   * (`categoryMap.insert`, 0x005560B0 -- `Address:` on
   * `rb_tree::insert_unique`, RbTree.h), then sets this blueprint's bit in
   * that node's `BVIntSet`. The binary reaches the set as `node + 56`,
   * which is `it->second.Bits()` here (`CategoryLookupValue` inherits
   * `CategoryWordRangeView::Bits()`).
   *
   * FUN_00556320's role (previously unresolved): it is the compiler-emitted
   * 2-argument converting constructor of `CategoryLookupMap::value_type`
   * (`pair<const msvc8::string, CategoryLookupValue>`), materialising the
   * temporary this function passes to `insert()`. The binary builds that
   * temporary's second half inline as "an empty `BVIntSet` seeded with
   * `lookup->mWordUniverseHandle`" (0x00555601-0x00555625 hand-assembles a
   * `FastVectorN<uint,2>`-shaped empty vector on the stack, pointing its
   * inline storage at itself) rather than calling a named `ResetToEmpty` --
   * that inlining is why the key-assign and value-reset land in one fused
   * emission instead of the two-step shape a literal transcription of
   * `node->key = name; node->value.ResetToEmpty(handle);` would produce.
   * `FUN_00557310`, `buy_node`'s (FUN_005569C0) own value construction, is
   * the *other* `pair` constructor MSVC8 emits for this instantiation -- the
   * copy constructor invoked when `insert_at` copies the already-built
   * temporary into the freshly linked node. Both are `std::pair`
   * constructor emissions with no hand-written body of their own (RULE ONE);
   * writing `CategoryLookupMap::value_type(categoryName, freshValue)` below
   * is what makes the compiler emit both, matching the binary's two-step
   * construct-then-copy exactly.
   *
   * KNOWN FIDELITY DIVERGENCE (pre-existing, deliberately left alone here):
   * the binary has neither the `categoryName.empty()` early-out nor the two
   * `it == end()` guards below. `sub_5555C0` calls the lookup unconditionally
   * and dereferences the insert result without a null check. The guards are
   * defensive additions; removing them would restore 1:1 behavior, but this
   * lane is load-bearing for the whole unit-category system and the identity
   * of the bit-index field (`mCategoryBitIndex` here vs IDA's
   * `mBlueprintOrdinal`) is not independently confirmed, so that correction
   * is left for a pass that can verify it at runtime.
   */
  void AddCategoryMemberBit(
    EntityCategoryLookupTableRuntimeView& lookup,
    const msvc8::string& categoryName,
    const unsigned int categoryBitIndex
  )
  {
    if (categoryName.empty()) {
      return;
    }

    CategoryLookupMap& categoryMap = lookup.mCategoryMap;
    CategoryLookupMap::iterator it = categoryMap.find(categoryName);
    if (it == categoryMap.end()) {
      CategoryLookupValue freshValue{};
      freshValue.ResetToEmpty(lookup.mWordUniverseHandle);
      it = categoryMap.insert(CategoryLookupMap::value_type(categoryName, freshValue)).first;
    }
    if (it == categoryMap.end()) {
      return;
    }

    (void)it->second.Bits().Add(categoryBitIndex);
  }

  /**
   * Address: 0x005289D0 (FUN_005289D0, func_RegisterBlueprint)
   *
   * IDA signature:
   * int __thiscall func_RegisterBlueprint(Moho::RUnitBlueprint *this,
   *                                        Moho::RRuleGameRulesImpl *a2,
   *                                        char *a3);
   *
   * Callers (all 6 confirmed via `FUN_005289D0.xrefs.txt`, `type=17`/direct
   * call): `cfunc_RegisterUnitBlueprint` (0x00528AF0), `sub_528B90`
   * (0x00528B90, recovered here as `RegisterUnitBlueprintFromState`),
   * `cfunc_RegisterPropBlueprint` (0x00528BC0), `sub_528C60` (0x00528C60,
   * `RegisterPropBlueprintFromState`), `cfunc_RegisterProjectileBlueprint`
   * (0x00528C90), and `sub_528D30` (0x00528D30,
   * `RegisterProjectileBlueprintFromState`). The three `sub_528xx0` bodies
   * are wired to this helper by name below; the three `cfunc_Register*`
   * entry points (Sim.cpp, further down) reach it transitively by
   * delegating to those same `sub_528xx0` bodies rather than repeating the
   * call inline, matching this file's existing cast-and-forward pattern for
   * that trio.
   *
   * What it does:
   * Three-step sequence matching the binary exactly:
   *   1. For every string in `this->mCategories` (a msvc8-string vector),
   *      calls `sub_5555C0` (`Address:` on `AddCategoryMemberBit`,
   *      FUN_005555C0 above) with `a2->mEntityCategoryLookup` (read at
   *      `a2+0xC4`, `mov ecx, [eax+0C4h]` at 0x00528A26/0x00528A82/
   *      0x00528ABE) and the category name.
   *   2. If `a3` (the caller's extra implicit category, e.g. "ALLUNITS")
   *      is non-null, builds a temporary `std::string` from it and makes
   *      the same call.
   *   3. Unconditionally makes the same call a third time using the string
   *      at `this+8` (`Moho::REntityBlueprint::mBlueprintId`).
   *
   * KNOWN FIDELITY NOTES (left open, not fixed by this pass):
   *   - The binary has no null checks on `this`/`a2` and no empty-string
   *     guard on `a3` (`if (a3)` tests non-null only). This C++ body adds
   *     `!blueprint`/`!rules`/`!lookup` guards and an
   *     `extraCategory != nullptr && *extraCategory != '\0'` check as
   *     defensive additions, matching the same kind of divergence already
   *     documented on `AddCategoryMemberBit` above.
   *   - This function's own asm reads `this->mCategories.begin()`/`end()`
   *     (`_Myfirst`/`_Mylast`) at `this+0x64`/`this+0x68`
   *     (`mov eax,[esi+64h]` / `mov ecx,[esi+68h]` at
   *     0x005289F2/0x005289FC), which looked at first glance like it
   *     disagreed with the header's `offsetof(REntityBlueprint,
   *     mCategories) == 0x60` and with `REntityBlueprintTypeInfo::AddFields`
   *     (FUN_00512870, `push 60h` for the reflected "Categories" field).
   *     It does not: `msvc8::vector<T>` in this codebase is 16 bytes
   *     (leading `myProxy_` before `first_`/`last_`/`end_`, matching VC8's
   *     `_SECURE_SCL=1` `_Container_base12` proxy word), so `begin()`/
   *     `end()` sit at the vector object's `+0x4`/`+0x8` -- `this+0x64`/
   *     `this+0x68` -- when the vector itself starts at `this+0x60`, exactly
   *     as reflection says. `REntityBlueprint::~REntityBlueprint`
   *     (FUN_00511E80) confirms this directly: it computes `this+0x60` once
   *     (`lea edi,[esi+60h]`) and its address-taken subobject-destructor
   *     trampoline does `add ecx,60h` immediately before tail-calling
   *     `??1vector_string@std@@QAE@@Z` (`std::vector<std::string>::
   *     ~vector()`) -- the linker's own mangled-symbol proof that the
   *     vector lives at `+0x60`. All sources agree; `blueprint->mCategories`
   *     below already reads the correct field via `begin()`/`end()`.
   */
  void RegisterBlueprintCategoryMembership(
    REntityBlueprint* const blueprint,
    RRuleGameRulesImpl* const rules,
    const char* const extraCategory
  )
  {
    if (!blueprint || !rules) {
      return;
    }

    EntityCategoryLookupTableRuntimeView* const lookup = ResolveEntityCategoryLookupTable(*rules);
    if (!lookup) {
      return;
    }

    const unsigned int categoryBitIndex = blueprint->mCategoryBitIndex;
    for (const msvc8::string& category : blueprint->mCategories) {
      AddCategoryMemberBit(*lookup, category, categoryBitIndex);
    }

    if (extraCategory != nullptr && *extraCategory != '\0') {
      AddCategoryMemberBit(*lookup, msvc8::string(extraCategory), categoryBitIndex);
    }

    AddCategoryMemberBit(*lookup, blueprint->mBlueprintId, categoryBitIndex);
  }

  void InitUnitBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RUnitBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    (void)gpg::RRef_RUnitBlueprint(&destination, blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    (void)gpg::RRef_RUnitBlueprint(&resolved, blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  void InitPropBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RPropBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    (void)gpg::RRef_RPropBlueprint(&destination, blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    (void)gpg::RRef_RPropBlueprint(&resolved, blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  void InitProjectileBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RProjectileBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    (void)gpg::RRef_RProjectileBlueprint(&destination, blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    (void)gpg::RRef_RProjectileBlueprint(&resolved, blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  void InitMeshBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RMeshBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    (void)gpg::RRef_RMeshBlueprint(&destination, blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    (void)gpg::RRef_RMeshBlueprint(&resolved, blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  [[nodiscard]] LuaPlus::LuaObject EnsureLuaBlueprintTable(LuaPlus::LuaState* const state)
  {
    if (!state) {
      return {};
    }

    LuaPlus::LuaObject allBlueprints = state->GetGlobal("__blueprints");
    if (allBlueprints.IsTable()) {
      return allBlueprints;
    }

    LuaPlus::LuaObject globals = state->GetGlobals();
    LuaPlus::LuaObject replacement{};
    replacement.AssignNewTable(state, 0, 0);
    globals.SetObject("__blueprints", replacement);
    return state->GetGlobal("__blueprints");
  }

  /**
   * Address: 0x00529B30 (FUN_00529B30, func_Add__blueprints) - by-ordinal lane
   *
   * What it does:
   * Ground truth publishes the Lua blueprint object into `__blueprints`
   * TWICE: first by ordinal (`__blueprints[mBlueprintOrdinal] = luaBlueprint`,
   * read directly off `FUN_00529B30`'s own pseudocode: `SetObject(Global,
   * mBlueprintOrdinal, a1)`), then by string name. This function previously
   * only recovered the by-name half; the by-ordinal `SetObject` call below
   * completes it. `RBlueprint::GetLuaBlueprint` (RBlueprint.cpp, ground
   * truth FUN_0050DF90) reads back ONLY via the ordinal index
   * (`__blueprints[mBlueprintOrdinal]`) - every Lua-side `unit:GetBlueprint()`
   * call (cfunc_UserUnitGetBlueprintL/cfunc_EntityGetBlueprintL, both call
   * this same GetLuaBlueprint) depends on this half existing.
   */
  void PublishLuaBlueprint(
    LuaPlus::LuaObject& luaBlueprint,
    void* const blueprintObject,
    RRuleGameRulesImpl* const rules
  )
  {
    const RBlueprint* const blueprint = reinterpret_cast<const RBlueprint*>(blueprintObject);
    if (!rules || !rules->mLuaState || !blueprint) {
      return;
    }

    LuaPlus::LuaObject allBlueprints = EnsureLuaBlueprintTable(rules->mLuaState);
    if (!allBlueprints.IsTable()) {
      return;
    }

    allBlueprints.SetObject(blueprint->mBlueprintOrdinal, luaBlueprint);
    allBlueprints.SetObject(blueprint->mBlueprintId.c_str(), luaBlueprint);
  }

  [[nodiscard]] msvc8::string ResolveNormalizedBlueprintId(const LuaPlus::LuaObject& blueprintSpec)
  {
    LuaPlus::LuaObject idObject = blueprintSpec.GetByName("BlueprintId");
    const char* const rawId = idObject.GetString();
    return gpg::STR_ToLower(rawId ? rawId : "");
  }

  /**
   * Address: 0x00529B30 (FUN_00529B30, func_Add__blueprints) -- by-ordinal
   * and by-name Lua publication lanes
   *
   * What it does:
   * The binary's blueprint registration chain calls `func_Add__blueprints`
   * after each blueprint registration to publish the blueprint into
   * `__blueprints` Lua global by ordinal and by string-name keys, then
   * iterate `rules->mMaps` and register the blueprint's ordinal into every
   * connected export binding's pending set. The recovered code retains the
   * by-string-name Lua publication via `PublishLuaBlueprint`, the
   * ordinal-vector append via `AppendBlueprintOrdinal`, and (now that
   * `RRuleGameRulesImpl::mMaps` is modeled -- see RRuleGameRules.h) the
   * `mMaps` iteration via `RegisterBlueprintInCategoryMaps`, which is what
   * `func_MapInsert` / `FUN_0052BC60`'s role in this loop absorbs into.
   *
   * The by-ordinal Lua `SetObject` path is still elided: the category
   * bit-set / Lua ordinal publication for that specific lane is routed
   * through `mEntityCategoryLookup` + `BlueprintOrdinalVector`, which take
   * a different shape than the binary's flat array here.
   */
  template <typename TBlueprint, typename Initializer>
  [[nodiscard]] TBlueprint* GetOrCreateRegisteredBlueprint(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules,
    RRuleGameRulesBlueprintMap& map,
    const char* const blueprintTypeName,
    Initializer initializer
  )
  {
    if (!state || !state->m_state || !rules) {
      return nullptr;
    }

    LuaPlus::LuaObject blueprintSpec(LuaPlus::LuaStackObject(state, 1));
    const msvc8::string normalizedId = ResolveNormalizedBlueprintId(blueprintSpec);

    const msvc8::string logContextText =
      gpg::STR_Printf("Initializing %s blueprint for %s", blueprintTypeName, normalizedId.c_str());
    gpg::ScopedLogContext logScope(logContextText);
    if (CFG_GetArgOption("/spewbp", 0u, nullptr)) {
      gpg::Logf("Initializing %s blueprint for %s", blueprintTypeName, normalizedId.c_str());
    }

    TBlueprint* blueprint = nullptr;
    if (const auto found = map.find(normalizedId); found != map.end()) {
      blueprint = static_cast<TBlueprint*>(found->second);
    }

    if (!blueprint) {
      RResId resourceId{};
      gpg::STR_CopyFilename(&resourceId.name, &normalizedId);

      blueprint = new (std::nothrow) TBlueprint(rules, resourceId);
      if (!blueprint) {
        return nullptr;
      }

      const auto inserted = map.insert(RRuleGameRulesBlueprintMap::value_type(normalizedId, blueprint));
      if (!inserted.second) {
        delete blueprint;
        return nullptr;
      }

      AppendBlueprintOrdinal(*rules, blueprint);
      RegisterBlueprintInCategoryMaps(*rules, blueprint);
    }

    initializer(blueprintSpec, blueprint);
    PublishLuaBlueprint(blueprintSpec, blueprint, rules);
    return blueprint;
  }

  template <typename TBlueprint, typename RefBuilder>
  [[nodiscard]] TBlueprint* GetOrCreateRegisteredEffectBlueprint(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules,
    RRuleGameRulesBlueprintMap& map,
    const char* const blueprintTypeName,
    RefBuilder refBuilder
  )
  {
    if (!state || !state->m_state || !rules) {
      return nullptr;
    }

    LuaPlus::LuaObject blueprintSpec(LuaPlus::LuaStackObject(state, 1));
    const msvc8::string normalizedId = ResolveNormalizedBlueprintId(blueprintSpec);

    const msvc8::string logContextText =
      gpg::STR_Printf("Initializing %s blueprint for %s", blueprintTypeName, normalizedId.c_str());
    gpg::ScopedLogContext logScope(logContextText);

    TBlueprint* blueprint = nullptr;
    if (const auto found = map.find(normalizedId); found != map.end()) {
      blueprint = static_cast<TBlueprint*>(found->second);
    }

    if (!blueprint) {
      blueprint = new (std::nothrow) TBlueprint();
      if (!blueprint) {
        return nullptr;
      }

      blueprint->mOwnerRules = rules;
      gpg::STR_CopyFilename(&blueprint->BlueprintId.name, &normalizedId);

      const auto inserted = map.insert(RRuleGameRulesBlueprintMap::value_type(normalizedId, blueprint));
      if (!inserted.second) {
        delete blueprint;
        return nullptr;
      }
    }

    gpg::RRef destination{};
    (void)refBuilder(&destination, blueprint);

    LuaPlus::LuaObject source(blueprintSpec);
    (void)SCR_LuaBuildObject(source, destination, true);
    return blueprint;
  }

  // Recovered helper chain for FUN_00528B90/FUN_00528C60/FUN_00528D30:
  // create-or-lookup blueprint object, apply Lua data to reflected fields,
  // mirror into __blueprints, and publish category-bit membership.

  /**
   * Address: 0x00532080 (FUN_00532080, func_CreateRPropBlueprint)
   *
   * What it does:
   * Creates or resolves one prop blueprint from Lua stack lane 1, applies Lua
   * payload fields, and publishes the merged object into `__blueprints`.
   */
  [[nodiscard]] RPropBlueprint* CreateOrGetPropBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RPropBlueprint>(
      state,
      rules,
      rules->mPropBlueprints,
      "prop",
      [](LuaPlus::LuaObject& blueprintSpec, RPropBlueprint* const propBlueprint) {
        InitPropBlueprintFromLua(blueprintSpec, propBlueprint);
      }
    );
  }

  /**
   * Address: 0x00531D80 (FUN_00531D80, func_CreateRUnitBlueprint)
   *
   * What it does:
   * Creates or resolves one unit blueprint from Lua stack lane 1, applies Lua
   * payload fields, and publishes the merged object into `__blueprints`.
   */
  [[nodiscard]] RUnitBlueprint* CreateOrGetUnitBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RUnitBlueprint>(
      state,
      rules,
      rules->mUnitBlueprints,
      "unit",
      [](LuaPlus::LuaObject& blueprintSpec, RUnitBlueprint* const unitBlueprint) {
        InitUnitBlueprintFromLua(blueprintSpec, unitBlueprint);
      }
    );
  }

  /**
   * Address: 0x00528B90 (FUN_00528B90)
   *
   * What it does:
   * Registers one unit blueprint from Lua into the rules unit map, updates
   * the ordinal/__blueprints lanes, and inserts category bits (including
   * implicit ALLUNITS membership).
   */
  int RegisterUnitBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RUnitBlueprint* const blueprint = CreateOrGetUnitBlueprintFromState(state, rules);
    RegisterBlueprintCategoryMembership(blueprint, rules, "ALLUNITS");
    return 0;
  }

  /**
   * Address: 0x00528C60 (FUN_00528C60)
   *
   * What it does:
   * Registers one prop blueprint from Lua into the rules prop map, updates
   * the ordinal/__blueprints lanes, and publishes category-bit membership
   * from Blueprint.Categories plus blueprint id.
   */
  int RegisterPropBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RPropBlueprint* const blueprint = CreateOrGetPropBlueprintFromState(state, rules);
    RegisterBlueprintCategoryMembership(blueprint, rules, nullptr);
    return 0;
  }

  /**
   * Address: 0x00532380 (FUN_00532380, func_CreateRProjectileBlueprint)
   *
   * What it does:
   * Creates or resolves one projectile blueprint from Lua stack lane 1,
   * applies Lua payload fields, and publishes the merged object into
   * `__blueprints`.
   */
  [[nodiscard]] RProjectileBlueprint* CreateOrGetProjectileBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RProjectileBlueprint>(
      state,
      rules,
      rules->mProjectileBlueprints,
      "projectile",
      [](LuaPlus::LuaObject& blueprintSpec, RProjectileBlueprint* const projectileBlueprint) {
        InitProjectileBlueprintFromLua(blueprintSpec, projectileBlueprint);
      }
    );
  }

  /**
   * Address: 0x00528D30 (FUN_00528D30)
   *
   * What it does:
   * Registers one projectile blueprint from Lua into the rules projectile
   * map, updates the ordinal/__blueprints lanes, and inserts category bits
   * (including implicit ALLPROJECTILES membership).
   */
  int RegisterProjectileBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RProjectileBlueprint* const blueprint = CreateOrGetProjectileBlueprintFromState(state, rules);
    RegisterBlueprintCategoryMembership(blueprint, rules, "ALLPROJECTILES");
    return 0;
  }

  /**
   * Address: 0x00532680 (FUN_00532680, func_RegisterMeshBlueprint)
   *
   * What it does:
   * Creates or resolves one mesh blueprint from Lua stack lane 1, applies Lua
   * payload fields, and publishes the merged object into `__blueprints`.
   */
  [[nodiscard]] RMeshBlueprint* CreateOrGetMeshBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RMeshBlueprint>(
      state,
      rules,
      rules->mMeshBlueprints,
      "mesh",
      [](LuaPlus::LuaObject& blueprintSpec, RMeshBlueprint* const meshBlueprint) {
        InitMeshBlueprintFromLua(blueprintSpec, meshBlueprint);
      }
    );
  }

  int RegisterMeshBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RMeshBlueprint* const blueprint = CreateOrGetMeshBlueprintFromState(state, rules);
    (void)blueprint;
    return 0;
  }

  /**
   * Address: 0x00532980 (FUN_00532980, func_RegisterTrailEmitterBlueprint)
   *
   * What it does:
   * Creates or resolves one trail-emitter blueprint from Lua stack lane 1,
   * then applies reflected field values from the Lua object into that
   * blueprint instance.
   */
  int RegisterTrailEmitterBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    (void)GetOrCreateRegisteredEffectBlueprint<RTrailBlueprint>(
      state,
      rules,
      rules->mTrailBlueprints,
      "trail emitter",
      [](gpg::RRef* const out, RTrailBlueprint* const trailBlueprint) {
        return gpg::RRef_RTrailBlueprint(out, trailBlueprint);
      }
    );
    return 0;
  }

  /**
   * Address: 0x00532C10 (FUN_00532C10, func_RegisterEmitterBlueprint)
   *
   * What it does:
   * Creates or resolves one particle-emitter blueprint from Lua stack lane 1,
   * then applies reflected field values from the Lua object into that
   * blueprint instance.
   */
  int RegisterEmitterBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    (void)GetOrCreateRegisteredEffectBlueprint<REmitterBlueprint>(
      state,
      rules,
      rules->mEmitterBlueprints,
      "particle emitter",
      [](gpg::RRef* const out, REmitterBlueprint* const emitterBlueprint) {
        return gpg::RRef_REmitterBlueprint(out, emitterBlueprint);
      }
    );
    return 0;
  }

  /**
   * Address: 0x00532EC0 (FUN_00532EC0, func_RegisterBeamBlueprint)
   *
   * What it does:
   * Creates or resolves one beam blueprint from Lua stack lane 1, then applies
   * reflected field values from the Lua object into that blueprint instance.
   */
  int RegisterBeamBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    (void)GetOrCreateRegisteredEffectBlueprint<RBeamBlueprint>(
      state,
      rules,
      rules->mBeamBlueprints,
      "beam effect",
      [](gpg::RRef* const out, RBeamBlueprint* const beamBlueprint) {
        return gpg::RRef_RBeamBlueprint(out, beamBlueprint);
      }
    );
    return 0;
  }

  /**
   * Address: 0x00528DF0 (FUN_00528DF0)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one mesh-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterMeshBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mMeshBlueprints;
    (void)RegisterMeshBlueprintFromState(state);
    return 0;
  }

  /**
   * Address: 0x00528EB0 (FUN_00528EB0)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one trail-emitter
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterTrailEmitterBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mTrailBlueprints;
    return RegisterTrailEmitterBlueprintFromState(state);
  }

  /**
   * Address: 0x00528F60 (FUN_00528F60)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one emitter-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterEmitterBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mEmitterBlueprints;
    return RegisterEmitterBlueprintFromState(state);
  }

  /**
   * Address: 0x00529010 (FUN_00529010)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one beam-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterBeamBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mBeamBlueprints;
    return RegisterBeamBlueprintFromState(state);
  }
} // namespace

/**
 * Address: 0x00528AF0 (FUN_00528AF0, cfunc_RegisterUnitBlueprint)
 *
 * What it does:
 * Casts the raw callback state and forwards unit-blueprint registration into
 * the fast-path helper lane.
 */
int moho::cfunc_RegisterUnitBlueprint(lua_State* const luaContext)
{
  return RegisterUnitBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528BC0 (FUN_00528BC0, cfunc_RegisterPropBlueprint)
 *
 * What it does:
 * Casts the raw callback state and forwards prop-blueprint registration into
 * the fast-path helper lane.
 */
int moho::cfunc_RegisterPropBlueprint(lua_State* const luaContext)
{
  return RegisterPropBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528C90 (FUN_00528C90, cfunc_RegisterProjectileBlueprint)
 *
 * What it does:
 * Casts the raw callback state and forwards projectile-blueprint registration
 * into the fast-path helper lane.
 */
int moho::cfunc_RegisterProjectileBlueprint(lua_State* const luaContext)
{
  return RegisterProjectileBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528D60 (FUN_00528D60, cfunc_RegisterMeshBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches mesh-blueprint registration into
 * the rules mesh map lane.
 */
int moho::cfunc_RegisterMeshBlueprint(lua_State* const luaContext)
{
  return RegisterMeshBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528E20 (FUN_00528E20, cfunc_RegisterTrailEmitterBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches trail-emitter blueprint
 * registration into the rules trail map lane.
 */
int moho::cfunc_RegisterTrailEmitterBlueprint(lua_State* const luaContext)
{
  return RegisterTrailEmitterBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528ED0 (FUN_00528ED0, cfunc_RegisterEmitterBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches emitter blueprint registration
 * into the rules emitter map lane.
 */
int moho::cfunc_RegisterEmitterBlueprint(lua_State* const luaContext)
{
  return RegisterEmitterBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x00528F80 (FUN_00528F80, cfunc_RegisterBeamBlueprint)
 *
 * What it does:
 * Casts the raw callback state and dispatches beam blueprint registration into
 * the rules beam map lane.
 */
int moho::cfunc_RegisterBeamBlueprint(lua_State* const luaContext)
{
  return RegisterBeamBlueprintFromState(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x005284F0 (FUN_005284F0, func_SpecFootprints_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SpecFootprints`.
 */
moho::CScrLuaInitForm* moho::func_SpecFootprints_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "SpecFootprints",
    &moho::cfunc_SpecFootprints,
    nullptr,
    "<global>",
    kSpecFootprintsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528B30 (FUN_00528B30, func_RegisterUnitBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterUnitBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterUnitBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterUnitBlueprint",
    &moho::cfunc_RegisterUnitBlueprint,
    nullptr,
    "<global>",
    kRegisterUnitBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528C00 (FUN_00528C00, func_RegisterPropBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterPropBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterPropBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterPropBlueprint",
    &moho::cfunc_RegisterPropBlueprint,
    nullptr,
    "<global>",
    kRegisterPropBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528CD0 (FUN_00528CD0, func_RegisterProjectileBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterProjectileBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterProjectileBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterProjectileBlueprint",
    &moho::cfunc_RegisterProjectileBlueprint,
    nullptr,
    "<global>",
    kRegisterProjectileBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528D90 (FUN_00528D90, func_RegisterMeshBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterMeshBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterMeshBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterMeshBlueprint",
    &moho::cfunc_RegisterMeshBlueprint,
    nullptr,
    "<global>",
    kRegisterMeshBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528E50 (FUN_00528E50, func_RegisterTrailEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterTrailEmitterBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterTrailEmitterBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterTrailEmitterBlueprint",
    &moho::cfunc_RegisterTrailEmitterBlueprint,
    nullptr,
    "<global>",
    kRegisterTrailEmitterBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528F00 (FUN_00528F00, func_RegisterEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterEmitterBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterEmitterBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterEmitterBlueprint",
    &moho::cfunc_RegisterEmitterBlueprint,
    nullptr,
    "<global>",
    kRegisterEmitterBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00528FB0 (FUN_00528FB0, func_RegisterBeamBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `RegisterBeamBlueprint`.
 */
moho::CScrLuaInitForm* moho::func_RegisterBeamBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "RegisterBeamBlueprint",
    &moho::cfunc_RegisterBeamBlueprint,
    nullptr,
    "<global>",
    kRegisterBeamBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00529030 (FUN_00529030, cfunc_BlueprintLoaderUpdateProgress)
 *
 * What it does:
 * Casts the Lua callback state and ticks the current background-load progress
 * control stored in the worker TLS lane when present.
 */
namespace
{
  void TickBlueprintLoaderProgressFromLoaderContext()
  {
    moho::CBackgroundTaskControl* const initHandler = moho::BlueprintLoaderContext().mInitHandler;
    if (initHandler != nullptr && initHandler->mHandle != nullptr) {
      initHandler->mHandle->UpdateLoadingProgress();
    }
  }

  /**
   * Address: 0x005290C0 (FUN_005290C0)
   *
   * What it does:
   * Ticks one background-load progress update directly from the worker's
   * blueprint-loader context and returns the legacy success code.
   */
  [[maybe_unused]] int BlueprintLoaderUpdateProgressFromLoaderContext()
  {
    TickBlueprintLoaderProgressFromLoaderContext();
    return 0;
  }
} // namespace

int moho::cfunc_BlueprintLoaderUpdateProgress(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);
  TickBlueprintLoaderProgressFromLoaderContext();
  return 0;
}

/**
 * Address: 0x00529060 (FUN_00529060, func_BlueprintLoaderUpdateProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-Lua binder definition for `BlueprintLoaderUpdateProgress`.
 */
moho::CScrLuaInitForm* moho::func_BlueprintLoaderUpdateProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "BlueprintLoaderUpdateProgress",
    &moho::cfunc_BlueprintLoaderUpdateProgress,
    nullptr,
    "<global>",
    kBlueprintLoaderUpdateProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC8E50 (FUN_00BC8E50, register_RegisterUnitBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterUnitBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterUnitBlueprint_LuaFuncDef()
{
  return func_RegisterUnitBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E60 (FUN_00BC8E60, register_RegisterPropBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterPropBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterPropBlueprint_LuaFuncDef()
{
  return func_RegisterPropBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E70 (FUN_00BC8E70, register_RegisterProjectileBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterProjectileBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterProjectileBlueprint_LuaFuncDef()
{
  return func_RegisterProjectileBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E80 (FUN_00BC8E80, register_RegisterMeshBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterMeshBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterMeshBlueprint_LuaFuncDef()
{
  return func_RegisterMeshBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E90 (FUN_00BC8E90, register_RegisterTrailEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterTrailEmitterBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterTrailEmitterBlueprint_LuaFuncDef()
{
  return func_RegisterTrailEmitterBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EA0 (FUN_00BC8EA0, register_RegisterEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterEmitterBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterEmitterBlueprint_LuaFuncDef()
{
  return func_RegisterEmitterBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EB0 (FUN_00BC8EB0, j_func_RegisterBeamBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterBeamBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_RegisterBeamBlueprint_LuaFuncDef()
{
  return func_RegisterBeamBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EC0 (FUN_00BC8EC0, j_func_BlueprintLoaderUpdateProgress_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_BlueprintLoaderUpdateProgress_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_BlueprintLoaderUpdateProgress_LuaFuncDef()
{
  return func_BlueprintLoaderUpdateProgress_LuaFuncDef();
}

/**
 * Address: 0x00758F90 (FUN_00758F90, cfunc_RandomSim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_RandomSimL`.
 */
int moho::cfunc_RandomSim(lua_State* const luaContext)
{
  return cfunc_RandomSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00758FB0 (FUN_00758FB0, func_RandomSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane Lua binder definition for global `Random`.
 */
moho::CScrLuaInitForm* moho::func_RandomSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "Random",
    &moho::cfunc_RandomSim,
    nullptr,
    "<global>",
    kRandomSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759010 (FUN_00759010, cfunc_RandomSimL)
 *
 * What it does:
 * Produces one random float or integer range sample from the active sim
 * random stream for `Random([[min,] max])`.
 */
int moho::cfunc_RandomSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kRandomSimHelpText,
      0,
      2,
      argumentCount
    );
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  if (!sim) {
    LuaPlus::LuaState::Error(state, "Random(): can only be called as part of the sim.");
  }

  if (argumentCount == 0) {
    const double value = static_cast<double>(sim->mRngState->twister.NextUInt32()) * 2.3283064e-10;
    lua_pushnumber(rawState, value);
    return 1;
  }

  if (argumentCount == 1) {
    const int maxValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
    const std::uint32_t randomValue = sim->mRngState->twister.NextUInt32();
    const std::uint32_t scaledValue = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(maxValue)) * static_cast<std::uint64_t>(randomValue)) >>
      32u
    );
    const int result = static_cast<int>(scaledValue + 1u);
    lua_pushnumber(rawState, static_cast<float>(result));
    return 1;
  }

  const int minValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
  const int maxValue = LuaPlus::LuaStackObject(state, 2).GetInteger();
  const std::uint32_t randomValue = sim->mRngState->twister.NextUInt32();
  const std::uint32_t span = (static_cast<std::uint32_t>(maxValue) + 1u) - static_cast<std::uint32_t>(minValue);
  const std::uint32_t scaledOffset =
    static_cast<std::uint32_t>((static_cast<std::uint64_t>(span) * static_cast<std::uint64_t>(randomValue)) >> 32u);
  const int result = static_cast<int>(static_cast<std::uint32_t>(minValue) + scaledOffset);
  lua_pushnumber(rawState, static_cast<float>(result));
  return 1;
}

/**
 * Address: 0x007593D0 (FUN_007593D0, cfunc_SelectedUnit)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SelectedUnitL`.
 */
int moho::cfunc_SelectedUnit(lua_State* const luaContext)
{
  return cfunc_SelectedUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007593F0 (FUN_007593F0, func_SelectedUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `SelectedUnit()`.
 */
moho::CScrLuaInitForm* moho::func_SelectedUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SelectedUnit",
    &moho::cfunc_SelectedUnit,
    nullptr,
    "<global>",
    kSelectedUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759450 (FUN_00759450, cfunc_SelectedUnitL)
 *
 * What it does:
 * Pushes the current `__selected_unit` global value.
 */
int moho::cfunc_SelectedUnitL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  LuaPlus::LuaObject selectedUnit = state->GetGlobals()["__selected_unit"];
  selectedUnit.PushStack(state);
  return 1;
}

/**
 * Address: 0x007594C0 (FUN_007594C0, cfunc_SimConExecute)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SimConExecuteL`.
 */
int moho::cfunc_SimConExecute(lua_State* const luaContext)
{
  return cfunc_SimConExecuteL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007594E0 (FUN_007594E0, func_SimConExecute_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SimConExecute`.
 */
moho::CScrLuaInitForm* moho::func_SimConExecute_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SimConExecute",
    &moho::cfunc_SimConExecute,
    nullptr,
    "<global>",
    kSimConExecuteHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759540 (FUN_00759540, cfunc_SimConExecuteL)
 *
 * What it does:
 * Reads one console command string and executes it.
 */
int moho::cfunc_SimConExecuteL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSimConExecuteHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject commandArg(state, 1);
  const char* commandText = lua_tostring(rawState, 1);
  if (!commandText) {
    commandArg.TypeError("string");
    commandText = "";
  }

  CON_Execute(commandText);
  return 0;
}

/**
 * Address: 0x0075D060 (FUN_0075D060, cfunc_TryCopyPose)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_TryCopyPoseL`.
 */
int moho::cfunc_TryCopyPose(lua_State* const luaContext)
{
  return cfunc_TryCopyPoseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075D080 (FUN_0075D080, func_TryCopyPose_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `TryCopyPose`. The binary's
 * only caller is the tail-call trampoline `register_TryCopyPose_LuaFuncDef`
 * (0x00BDC130, `jmp func_TryCopyPose_LuaFuncDef`); the recovered source
 * skips modeling that bridge and instead invokes this publisher directly
 * from `SimLuaFuncDefBootstrap`, matching every other sibling in this file
 * (`func_RandomSim_LuaFuncDef`, `func_SelectedUnit_LuaFuncDef`, ...).
 */
moho::CScrLuaInitForm* moho::func_TryCopyPose_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "TryCopyPose",
    &moho::cfunc_TryCopyPose,
    nullptr,
    "<global>",
    kTryCopyPoseHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075D0E0 (FUN_0075D0E0, cfunc_TryCopyPoseL)
 *
 * IDA signature:
 * int __cdecl cfunc_TryCopyPoseL(LuaPlus::LuaState *a1);
 *
 * What it does:
 * Resolves `unitFrom` (arg 1) and `entityTo` (arg 2) from the Lua stack.
 * When both share the same mesh and, if the meshes differ, the same
 * skeleton, retains `unitFrom`'s current animation pose. If
 * `bCopyWorldTransform` (arg 3) is false, clones that pose and re-anchors
 * the clone to `entityTo`'s current world transform instead of carrying
 * over the source's own transform (used when the destination was placed
 * somewhere other than the source's location, e.g. a wreck pulled back
 * onto the map). Queues the resulting `{entity id, pose}` pair onto the
 * Sim's pending pose-copy lane (`Sim::mPendingPoseCopies`, +0x9E8) and
 * returns whether the copy was attempted.
 */
int moho::cfunc_TryCopyPoseL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kTryCopyPoseHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject unitFromObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unitFrom = SCR_FromLua_Unit(unitFromObject);

  LuaPlus::LuaObject entityToObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const entityTo = SCR_FromLua_Entity(entityToObject, state);

  const bool sameMeshAndSkeleton =
    unitFrom->GetMesh().px == entityTo->GetMesh().px &&
    entityTo->GetMesh().px->GetSkeleton() == unitFrom->GetMesh().px->GetSkeleton();

  if (!sameMeshAndSkeleton) {
    lua_pushboolean(state->m_state, 0);
    return 1;
  }

  Sim* const sim = ResolveGlobalSim(state->m_state);

  SPendingPoseCopy pendingCopy{entityTo->id_, unitFrom->AniActor->GetPoseShared()};

  const bool bCopyWorldTransform = LuaPlus::LuaStackObject(state, 3).GetBoolean();
  if (!bCopyWorldTransform) {
    CAniPose* const clonedPose = new CAniPose(*pendingCopy.mPose);
    pendingCopy.mPose.reset(clonedPose);
    pendingCopy.mPose->SetWorldTransform(entityTo->GetTransformWm3());
  }

  sim->mPendingPoseCopies.push_back(pendingCopy);
  lua_pushboolean(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00759190 (FUN_00759190, cfunc_FlattenMapRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_FlattenMapRectL`.
 */
int moho::cfunc_FlattenMapRect(lua_State* const luaContext)
{
  return cfunc_FlattenMapRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007591B0 (FUN_007591B0, func_FlattenMapRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `FlattenMapRect`.
 */
moho::CScrLuaInitForm* moho::func_FlattenMapRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kFlattenMapRectName,
    &moho::cfunc_FlattenMapRect,
    nullptr,
    "<global>",
    kFlattenMapRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759210 (FUN_00759210, cfunc_FlattenMapRectL)
 *
 * What it does:
 * Reads `(x, z, sizex, sizez, elevation)` as `(x0, z0, x0+sizex, z0+sizez)`
 * plus a float elevation, then flattens that world rect on the global sim.
 */
int moho::cfunc_FlattenMapRectL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kFlattenMapRectHelpText, 5, argumentCount);
  }

  gpg::Rect2i rect{};

  LuaPlus::LuaStackObject arg1(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    arg1.TypeError("integer");
  }
  const int originX = static_cast<int>(lua_tonumber(rawState, 1));
  rect.x0 = originX;

  LuaPlus::LuaStackObject arg2(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    arg2.TypeError("integer");
  }
  const int originZ = static_cast<int>(lua_tonumber(rawState, 2));
  rect.z0 = originZ;

  LuaPlus::LuaStackObject arg3(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    arg3.TypeError("integer");
  }
  rect.x1 = originX + static_cast<int>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject arg4(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    arg4.TypeError("integer");
  }
  rect.z1 = originZ + static_cast<int>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject arg5(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    arg5.TypeError("number");
  }
  const float elevation = static_cast<float>(lua_tonumber(rawState, 5));

  Sim* const sim = lua_getglobaluserdata(rawState);
  sim->FlattenMapRect(rect, elevation);
  return 0;
}

/**
 * Address: 0x00759810 (FUN_00759810, cfunc_ParseEntityCategorySim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategorySimL`.
 */
int moho::cfunc_ParseEntityCategorySim(lua_State* const luaContext)
{
  return cfunc_ParseEntityCategorySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00759830 (FUN_00759830, func_ParseEntityCategorySim_LuaFuncDef)
 *
 * What it does:
 * Publishes the sim-lane global Lua binder for `ParseEntityCategory`.
 */
moho::CScrLuaInitForm* moho::func_ParseEntityCategorySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ParseEntityCategory",
    &moho::cfunc_ParseEntityCategorySim,
    nullptr,
    "<global>",
    kParseEntityCategorySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759890 (FUN_00759890, cfunc_ParseEntityCategorySimL)
 *
 * What it does:
 * Parses one category expression string and returns a new entity-category
 * userdata object.
 */
int moho::cfunc_ParseEntityCategorySimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kParseEntityCategorySimHelpText, 1, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  RRuleGameRulesImpl* const rules = sim ? static_cast<RRuleGameRulesImpl*>(sim->mRules) : nullptr;
  if (!rules) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  LuaPlus::LuaStackObject categoryTextArg(state, 1);
  const char* categoryText = lua_tostring(rawState, 1);
  if (!categoryText) {
    categoryTextArg.TypeError("string");
    categoryText = "";
  }

  EntityCategorySet parsedCategory = rules->ParseEntityCategory(categoryText);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &parsedCategory);
  out.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9B80 (FUN_008B9B80, cfunc_ParseEntityCategoryUserL)
 *
 * What it does:
 * Parses one category expression string and returns a new entity-category
 * userdata object.
 */
int moho::cfunc_ParseEntityCategoryUserL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kParseEntityCategoryUserHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  RRuleGameRulesImpl* const rules = session ? session->mRules : nullptr;
  if (!rules) {
    LuaPlus::LuaState::Error(state, kParseEntityCategoryUserNoSessionText);
  }

  LuaPlus::LuaStackObject categoryTextArg(state, 1);
  const char* categoryText = lua_tostring(rawState, 1);
  if (!categoryText) {
    categoryTextArg.TypeError("string");
    categoryText = "";
  }

  EntityCategorySet parsedCategory = rules->ParseEntityCategory(categoryText);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &parsedCategory);
  out.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9B00 (FUN_008B9B00, cfunc_ParseEntityCategoryUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategoryUserL`.
 */
int moho::cfunc_ParseEntityCategoryUser(lua_State* const luaContext)
{
  return cfunc_ParseEntityCategoryUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9B20 (FUN_008B9B20, func_ParseEntityCategoryUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ParseEntityCategory`.
 */
moho::CScrLuaInitForm* moho::func_ParseEntityCategoryUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ParseEntityCategory",
    &moho::cfunc_ParseEntityCategoryUser,
    nullptr,
    "<global>",
    kParseEntityCategoryUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759A10 (FUN_00759A10, cfunc_EntityCategoryContainsSimL)
 *
 * What it does:
 * Tests whether arg#1 category set contains arg#2 entity/blueprint category.
 */
int moho::cfunc_EntityCategoryContainsSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryContainsUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  Sim* const sim = ResolveGlobalSim(rawState);
  RRuleGameRulesImpl* const rules = sim ? static_cast<RRuleGameRulesImpl*>(sim->mRules) : nullptr;

  const LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));
  const REntityBlueprint* const blueprint = ResolveEntityCategoryCountBlueprint(valueObject, rules);

  const bool contains =
    categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  lua_pushboolean(rawState, contains ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00759990 (FUN_00759990, cfunc_EntityCategoryContainsSim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsSimL`.
 */
int moho::cfunc_EntityCategoryContainsSim(lua_State* const luaContext)
{
  return cfunc_EntityCategoryContainsSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007599B0 (FUN_007599B0, func_EntityCategoryContainsSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryContains`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryContainsSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryContains",
    &moho::cfunc_EntityCategoryContainsSim,
    nullptr,
    "<global>",
    kEntityCategoryContainsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759BD0 (FUN_00759BD0, cfunc_EntityCategoryFilterDownSim)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownSimL`.
 */
int moho::cfunc_EntityCategoryFilterDownSim(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterDownSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00759BF0 (FUN_00759BF0, func_EntityCategoryFilterDownSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterDownSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryFilterDown",
    &moho::cfunc_EntityCategoryFilterDownSim,
    nullptr,
    "<global>",
    kEntityCategoryFilterDownUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00759C50 (FUN_00759C50, cfunc_EntityCategoryFilterDownSimL)
 *
 * What it does:
 * Filters arg#2 values into a result table by keeping entries whose resolved
 * entity blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterDownSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryFilterDownUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  if (!sourceListObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kEntityCategoryCountInvalidTableText);
  }

  RRuleGameRulesImpl* const rules = ResolveRulesImpl(state);
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const REntityBlueprint* const blueprint = ResolveEntityCategoryCountBlueprint(valueObject, rules);
    if (categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.Insert(resultIndex, valueObject);
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00759F70 (FUN_00759F70, cfunc_EntityCategoryCountL)
 *
 * What it does:
 * Counts arg#2 list entries whose resolved blueprint category bit is present
 * in arg#1 category set.
 */
int moho::cfunc_EntityCategoryCountL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryCountHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);
  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  if (!sourceListObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kEntityCategoryCountInvalidTableText);
  }

  RRuleGameRulesImpl* const rules = ResolveRulesImpl(state);

  int categoryCount = 0;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const REntityBlueprint* const blueprint = ResolveEntityCategoryCountBlueprint(valueObject, rules);
    if (categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      ++categoryCount;
    }
  }

  lua_pushnumber(rawState, static_cast<float>(categoryCount));
  return 1;
}

/**
 * Address: 0x00759EF0 (FUN_00759EF0, cfunc_EntityCategoryCount)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryCountL`.
 */
int moho::cfunc_EntityCategoryCount(lua_State* const luaContext)
{
  return cfunc_EntityCategoryCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00759F10 (FUN_00759F10, func_EntityCategoryCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryCount`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryCount",
    &moho::cfunc_EntityCategoryCount,
    nullptr,
    "<global>",
    kEntityCategoryCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A1D0 (FUN_0075A1D0, cfunc_EntityCategoryCountAroundPosition)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to
 * `cfunc_EntityCategoryCountAroundPositionL`.
 */
int moho::cfunc_EntityCategoryCountAroundPosition(lua_State* const luaContext)
{
  return cfunc_EntityCategoryCountAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A1F0 (FUN_0075A1F0, func_EntityCategoryCountAroundPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `EntityCategoryCountAroundPosition`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryCountAroundPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EntityCategoryCountAroundPosition",
    &moho::cfunc_EntityCategoryCountAroundPosition,
    nullptr,
    "<global>",
    kEntityCategoryCountAroundPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A250 (FUN_0075A250, cfunc_EntityCategoryCountAroundPositionL)
 *
 * What it does:
 * Counts table entries whose entity category matches arg#1 and whose
 * horizontal distance from arg#3 is within arg#4.
 */
int moho::cfunc_EntityCategoryCountAroundPositionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kEntityCategoryCountAroundPositionHelpText,
      4,
      argumentCount
    );
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  if (!sourceListObject.IsTable()) {
    LuaPlus::LuaState::Error(state, kEntityCategoryCountInvalidTableText);
  }

  const LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vec3f center = SCR_FromLuaCopy<Wm3::Vector3<float>>(centerObject);

  LuaPlus::LuaStackObject radiusArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    radiusArg.TypeError("number");
  }

  const float radius = static_cast<float>(lua_tonumber(rawState, 4));
  const float radiusSquared = radius * radius;

  int categoryCount = 0;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    Entity* const entity = SCR_FromLuaNoError_Entity(valueObject);
    if (entity == nullptr || entity->BluePrint == nullptr || categorySet == nullptr) {
      continue;
    }

    const Wm3::Vec3f& entityPosition = entity->GetPositionWm3();
    const float deltaX = center.x - entityPosition.x;
    const float deltaZ = center.z - entityPosition.z;
    const float distanceSquared = (deltaX * deltaX) + (deltaZ * deltaZ);
    if (radiusSquared > distanceSquared && categorySet->Bits().Contains(entity->BluePrint->mCategoryBitIndex)) {
      ++categoryCount;
    }
  }

  lua_pushnumber(rawState, static_cast<float>(categoryCount));
  return 1;
}

/**
 * Address: 0x0075B940 (FUN_0075B940, cfunc_Warp)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WarpL`.
 */
int moho::cfunc_Warp(lua_State* const luaContext)
{
  return cfunc_WarpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075B9C0 (FUN_0075B9C0, cfunc_WarpL)
 *
 * What it does:
 * Reads `(entity, location [, orientation])` and warps the entity to
 * `location`; when arg#3 is absent/nil, preserves current entity orientation.
 */
int moho::cfunc_WarpL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kWarpHelpText,
      2,
      3,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vec3f location = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);

  VTransform transform = entity->GetTransformWm3();
  transform.pos_ = location;

  lua_settop(rawState, 3);
  if (lua_type(rawState, 3) != LUA_TNIL) {
    const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
    const LuaPlus::LuaObject xObject = orientationObject[1];
    const LuaPlus::LuaObject yObject = orientationObject[2];
    const LuaPlus::LuaObject zObject = orientationObject[3];
    const LuaPlus::LuaObject wObject = orientationObject[4];

    transform.orient_.x = static_cast<float>(xObject.GetNumber());
    transform.orient_.y = static_cast<float>(yObject.GetNumber());
    transform.orient_.z = static_cast<float>(zObject.GetNumber());
    transform.orient_.w = static_cast<float>(wObject.GetNumber());
  }

  entity->Warp(transform);
  return 0;
}

/**
 * Address: 0x0075B960 (FUN_0075B960, func_Warp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `Warp`.
 */
moho::CScrLuaInitForm* moho::func_Warp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "Warp",
    &moho::cfunc_Warp,
    nullptr,
    "<global>",
    kWarpHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075B650 (FUN_0075B650, cfunc_ChangeUnitArmyL)
 *
 * IDA signature:
 * void __thiscall cfunc_ChangeUnitArmyL(LuaPlus::LuaState *state);
 *
 * What it does:
 * Cheat command `ChangeUnitArmy(unit, armyIndex)`. Resolves the target unit and
 * army from the Lua stack, rejects transfers to the unit's own army, and — unless
 * one of the unit's attached entities is a COMMAND unit — transfers the unit and
 * its cargo to the new army through `Sim::TransferUnit`. Pushes the replacement
 * unit's Lua object on success, `nil` otherwise. Always returns 1.
 */
int moho::cfunc_ChangeUnitArmyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kChangeUnitArmyHelpText, 2, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata(rawState);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    // Faithful to FUN_0075B650: the worker independently validates the army lane.
    // (The recovered ARMY_FromLuaState already raises the Lua error for an invalid
    //  army, so this branch is defensive and mirrors the shipped worker.)
    LuaPlus::LuaStackObject armyStackObject(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      armyStackObject.TypeError("integer");
    }
    LuaPlus::LuaState::Error(state, "Invalid army %d", static_cast<int>(lua_tonumber(rawState, 2)));
  }

  if (unit->ArmyRef == army) {
    LuaPlus::LuaState::Error(state, "Unit already belongs to army %d", army->ArmyId);
  }

  // Disabled-validation predicate: the shipped binary computes this guard but the
  // conditional branch that consumed it was hot-patched to six NOPs
  // (asm 0x0075B816..0x0075B81B), so the result never gates behavior. Preserved for
  // fidelity.
  [[maybe_unused]] const bool sourceUnitIneligible =
    unit->IsBeingBuilt() || unit->IsDead() || unit->DestroyQueued() || unit->IsInCategory("COMMAND");

  // Refuse the transfer if any attached entity is a COMMAND unit.
  const msvc8::vector<Entity*>& attached = unit->GetAttachedEntities();
  for (Entity* const attachedEntity : attached) {
    Unit* const attachedUnit = attachedEntity->IsUnit();
    if (attachedUnit && attachedUnit->IsInCategory("COMMAND")) {
      lua_pushnil(rawState);
      return 1;
    }
  }

  Unit* const transferred = sim->TransferUnit(unit, army);
  if (transferred) {
    transferred->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
  }
  return 1;
}

/**
 * Address: 0x0075B5D0 (FUN_0075B5D0, cfunc_ChangeUnitArmy)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ChangeUnitArmyL`.
 */
int moho::cfunc_ChangeUnitArmy(lua_State* const luaContext)
{
  return cfunc_ChangeUnitArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075B5F0 (FUN_0075B5F0, func_ChangeUnitArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ChangeUnitArmy`.
 */
moho::CScrLuaInitForm* moho::func_ChangeUnitArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ChangeUnitArmy",
    &moho::cfunc_ChangeUnitArmy,
    nullptr,
    "<global>",
    kChangeUnitArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E2A0 (FUN_0075E2A0, cfunc_DebugGetSelection)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_DebugGetSelectionL`.
 */
int moho::cfunc_DebugGetSelection(lua_State* const luaContext)
{
  return cfunc_DebugGetSelectionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E2C0 (FUN_0075E2C0, func_DebugGetSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `DebugGetSelection`.
 */
moho::CScrLuaInitForm* moho::func_DebugGetSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DebugGetSelection",
    &moho::cfunc_DebugGetSelection,
    nullptr,
    "<global>",
    kDebugGetSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E320 (FUN_0075E320, cfunc_DebugGetSelectionL)
 *
 * What it does:
 * Returns a Lua table of script objects for ids in the active debug-selection
 * sync filter (`Sim::mSyncFilter.maskB`).
 */
int moho::cfunc_DebugGetSelectionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDebugGetSelectionHelpText, 0, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  BVIntSet selectedEntityIds{};
  CopyDebugSelectionMaskB(*sim, selectedEntityIds);

  LuaPlus::LuaObject selectionTable(state);
  selectionTable.AssignNewTable(state, 0, 0);

  std::int32_t tableIndex = 0;
  for (unsigned int nextEntityId = selectedEntityIds.GetNext(static_cast<unsigned int>(-1));
       nextEntityId != selectedEntityIds.Max();
       nextEntityId = selectedEntityIds.GetNext(nextEntityId))
  {
    Entity* const entity = FindEntityById(sim->mEntityDB, static_cast<EntId>(nextEntityId));
    if (entity == nullptr || entity->mLuaObj.IsNil()) {
      continue;
    }

    LuaPlus::LuaObject entityObject(entity->mLuaObj);
    ++tableIndex;
    selectionTable.SetObject(tableIndex, entityObject);
  }

  selectionTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075E4E0 (FUN_0075E4E0, cfunc_IsEntity)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsEntityL`.
 */
int moho::cfunc_IsEntity(lua_State* const luaContext)
{
  return cfunc_IsEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E500 (FUN_0075E500, func_IsEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsEntity`.
 */
moho::CScrLuaInitForm* moho::func_IsEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsEntity",
    &moho::cfunc_IsEntity,
    nullptr,
    "<global>",
    kIsEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E560 (FUN_0075E560, cfunc_IsEntityL)
 *
 * What it does:
 * Returns true when arg#1 resolves to an entity userdata object.
 */
int moho::cfunc_IsEntityL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsEntityHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject objectArg(LuaPlus::LuaStackObject(state, 1));
  const Entity* const entity = SCR_FromLuaNoError_Entity(objectArg);
  lua_pushboolean(rawState, entity ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0075E620 (FUN_0075E620, cfunc_IsUnit)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsUnitL`.
 */
int moho::cfunc_IsUnit(lua_State* const luaContext)
{
  return cfunc_IsUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E640 (FUN_0075E640, func_IsUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsUnit`.
 */
moho::CScrLuaInitForm* moho::func_IsUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsUnit",
    &moho::cfunc_IsUnit,
    nullptr,
    "<global>",
    kIsUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E6A0 (FUN_0075E6A0, cfunc_IsUnitL)
 *
 * What it does:
 * Returns arg#1 as unit Lua object when the entity is a unit; otherwise nil.
 */
int moho::cfunc_IsUnitL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsUnitHelpText);
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  return PushEntityScriptObjectOrNil(state, unit);
}

/**
 * Address: 0x0075E780 (FUN_0075E780, cfunc_IsProp)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsPropL`.
 */
int moho::cfunc_IsProp(lua_State* const luaContext)
{
  return cfunc_IsPropL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E7A0 (FUN_0075E7A0, func_IsProp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsProp`.
 */
moho::CScrLuaInitForm* moho::func_IsProp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsProp",
    &moho::cfunc_IsProp,
    nullptr,
    "<global>",
    kIsPropHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E800 (FUN_0075E800, cfunc_IsPropL)
 *
 * What it does:
 * Returns arg#1 as prop Lua object when the entity is a prop; otherwise nil.
 */
int moho::cfunc_IsPropL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsPropHelpText);
  Prop* const prop = entity ? entity->IsProp() : nullptr;
  return PushEntityScriptObjectOrNil(state, prop);
}

/**
 * Address: 0x0075E8E0 (FUN_0075E8E0, cfunc_IsBlip)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsBlipL`.
 */
int moho::cfunc_IsBlip(lua_State* const luaContext)
{
  return cfunc_IsBlipL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E900 (FUN_0075E900, func_IsBlip_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsBlip`.
 */
moho::CScrLuaInitForm* moho::func_IsBlip_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsBlip",
    &moho::cfunc_IsBlip,
    nullptr,
    "<global>",
    kIsBlipHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E960 (FUN_0075E960, cfunc_IsBlipL)
 *
 * What it does:
 * Returns arg#1 as recon-blip Lua object when the entity is a blip;
 * otherwise nil.
 */
int moho::cfunc_IsBlipL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsBlipHelpText);
  ReconBlip* const blip = entity ? entity->IsReconBlip() : nullptr;
  return PushEntityScriptObjectOrNil(state, blip);
}

/**
 * Address: 0x0075EA40 (FUN_0075EA40, cfunc_IsProjectile)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsProjectileL`.
 */
int moho::cfunc_IsProjectile(lua_State* const luaContext)
{
  return cfunc_IsProjectileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075EA60 (FUN_0075EA60, func_IsProjectile_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsProjectile`.
 */
moho::CScrLuaInitForm* moho::func_IsProjectile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsProjectile",
    &moho::cfunc_IsProjectile,
    nullptr,
    "<global>",
    kIsProjectileHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075EAC0 (FUN_0075EAC0, cfunc_IsProjectileL)
 *
 * What it does:
 * Returns arg#1 as projectile Lua object when the entity is a projectile;
 * otherwise nil.
 */
int moho::cfunc_IsProjectileL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsProjectileHelpText);
  Projectile* const projectile = entity ? entity->IsProjectile() : nullptr;
  return PushEntityScriptObjectOrNil(state, projectile);
}

/**
 * Address: 0x0075EBA0 (FUN_0075EBA0, cfunc_IsCollisionBeam)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsCollisionBeamL`.
 */
int moho::cfunc_IsCollisionBeam(lua_State* const luaContext)
{
  return cfunc_IsCollisionBeamL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075EBC0 (FUN_0075EBC0, func_IsCollisionBeam_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsCollisionBeam`.
 */
moho::CScrLuaInitForm* moho::func_IsCollisionBeam_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsCollisionBeam",
    &moho::cfunc_IsCollisionBeam,
    nullptr,
    "<global>",
    kIsCollisionBeamHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075EC20 (FUN_0075EC20, cfunc_IsCollisionBeamL)
 *
 * What it does:
 * Returns arg#1 as collision-beam Lua object when the entity is a collision
 * beam; otherwise nil.
 */
int moho::cfunc_IsCollisionBeamL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsCollisionBeamHelpText);
  CollisionBeamEntity* const collisionBeam = entity ? entity->IsCollisionBeam() : nullptr;
  return PushEntityScriptObjectOrNil(state, collisionBeam);
}

/**
 * Address: 0x00840840 (FUN_00840840, cfunc_GetUnitCommandFromCommandCap)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to
 * `cfunc_GetUnitCommandFromCommandCapL`.
 */
int moho::cfunc_GetUnitCommandFromCommandCap(lua_State* const luaContext)
{
  return cfunc_GetUnitCommandFromCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00840860 (FUN_00840860, func_GetUnitCommandFromCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `GetUnitCommandFromCommandCap`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitCommandFromCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetUnitCommandFromCommandCap",
    &moho::cfunc_GetUnitCommandFromCommandCap,
    nullptr,
    "<global>",
    kGetUnitCommandFromCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
 *
 * What it does:
 * Converts one command-capability enum into the matching unit command enum.
 */
moho::EUnitCommandType moho::UnitCommandCapToCommandType(const ERuleBPUnitCommandCaps commandCap)
{
  if (commandCap > RULEUCC_Tactical) {
    if (commandCap > RULEUCC_Pause) {
      if (commandCap > RULEUCC_Reclaim) {
        if (commandCap == RULEUCC_SpecialAction) {
          return EUnitCommandType::UNITCOMMAND_SpecialAction;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_Reclaim:
          return EUnitCommandType::UNITCOMMAND_Reclaim;
        case RULEUCC_Overcharge:
          return EUnitCommandType::UNITCOMMAND_OverCharge;
        case RULEUCC_Dive:
          return EUnitCommandType::UNITCOMMAND_Dive;
        default:
          break;
        }
      }
    } else {
      if (commandCap == RULEUCC_Pause) {
        return EUnitCommandType::UNITCOMMAND_Pause;
      }

      if (commandCap > RULEUCC_SiloBuildTactical) {
        if (commandCap == RULEUCC_SiloBuildNuke) {
          return EUnitCommandType::UNITCOMMAND_BuildSiloNuke;
        }
        if (commandCap == RULEUCC_Sacrifice) {
          return EUnitCommandType::UNITCOMMAND_Sacrifice;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_SiloBuildTactical:
          return EUnitCommandType::UNITCOMMAND_BuildSiloTactical;
        case RULEUCC_Teleport:
          return EUnitCommandType::UNITCOMMAND_Teleport;
        case RULEUCC_Ferry:
          return EUnitCommandType::UNITCOMMAND_Ferry;
        default:
          break;
        }
      }
    }

    return EUnitCommandType::UNITCOMMAND_None;
  }

  if (commandCap == RULEUCC_Tactical) {
    return EUnitCommandType::UNITCOMMAND_Tactical;
  }

  if (commandCap > RULEUCC_Repair) {
    if (commandCap > RULEUCC_CallTransport) {
      if (commandCap == RULEUCC_Nuke) {
        return EUnitCommandType::UNITCOMMAND_Nuke;
      }
    } else {
      switch (commandCap) {
      case RULEUCC_CallTransport:
        return EUnitCommandType::UNITCOMMAND_TransportLoadUnits;
      case RULEUCC_Capture:
        return EUnitCommandType::UNITCOMMAND_Capture;
      case RULEUCC_Transport:
        return EUnitCommandType::UNITCOMMAND_TransportUnloadUnits;
      default:
        break;
      }
    }

    return EUnitCommandType::UNITCOMMAND_None;
  }

  if (commandCap == RULEUCC_Repair) {
    return EUnitCommandType::UNITCOMMAND_Repair;
  }

  switch (commandCap) {
  case RULEUCC_Move:
    return EUnitCommandType::UNITCOMMAND_Move;
  case RULEUCC_Stop:
    return EUnitCommandType::UNITCOMMAND_Stop;
  case RULEUCC_Attack:
    return EUnitCommandType::UNITCOMMAND_Attack;
  case RULEUCC_Guard:
    return EUnitCommandType::UNITCOMMAND_Guard;
  case RULEUCC_Patrol:
    return EUnitCommandType::UNITCOMMAND_Patrol;
  default:
    return EUnitCommandType::UNITCOMMAND_None;
  }
}

/**
 * Address: 0x008408C0 (FUN_008408C0, cfunc_GetUnitCommandFromCommandCapL)
 *
 * What it does:
 * Converts one `RULEUCC` lexical token to its corresponding `UNITCOMMAND`
 * lexical token and returns it as a Lua string.
 */
int moho::cfunc_GetUnitCommandFromCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitCommandFromCommandCapErrorHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject commandCapArg(state, 1);
  const char* const commandCapLexical = lua_tostring(rawState, 1);
  if (commandCapLexical == nullptr) {
    commandCapArg.TypeError("string");
  }

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef commandCapRef(&commandCap, CachedERuleBPUnitCommandCapsType());
  (void)commandCapRef.SetLexical(commandCapLexical);

  EUnitCommandType commandType = moho::UnitCommandCapToCommandType(commandCap);

  gpg::RRef commandTypeRef(&commandType, CachedEUnitCommandTypeType());
  const msvc8::string commandTypeLexical = commandTypeRef.GetLexical();
  lua_pushstring(rawState, commandTypeLexical.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0088D970 (FUN_0088D970, cfunc_EjectSessionClientL)
 *
 * What it does:
 * Validates one client index argument and ejects the selected non-local
 * client from the active session.
 */
int moho::cfunc_EjectSessionClientL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEjectSessionClientHelpText, 1, argumentCount);
  }

  auto* const simDriver = dynamic_cast<CSimDriver*>(SIM_GetActiveDriver());
  if (simDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  IClientManager* const clientManager = simDriver->GetClientManager();
  if (clientManager == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  LuaPlus::LuaStackObject clientIndexArg{};
  clientIndexArg.m_state = state;
  clientIndexArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&clientIndexArg, "integer");
  }

  const int clientIndex = static_cast<int>(lua_tonumber(rawState, 1));
  const int clientCount = static_cast<int>(clientManager->NumberOfClients());
  if (clientIndex < 1 || clientIndex > clientCount) {
    LuaPlus::LuaState::Error(state, "Invalid client index %d, must be >= 1 and <= %d", clientIndex, clientCount);
  }

  IClient* const targetClient = clientManager->GetClient(clientIndex - 1);
  if (targetClient == nullptr) {
    LuaPlus::LuaState::Error(state, "Invalid client index %d, must be >= 1 and <= %d", clientIndex, clientCount);
  }

  if (targetClient == clientManager->GetLocalClient()) {
    LuaPlus::LuaState::Error(state, "Can't eject ourselves!");
  }

  targetClient->Eject();
  return 0;
}

/**
 * Address: 0x0088D8F0 (FUN_0088D8F0, cfunc_EjectSessionClient)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EjectSessionClientL`.
 */
int moho::cfunc_EjectSessionClient(lua_State* const luaContext)
{
  return cfunc_EjectSessionClientL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088D910 (FUN_0088D910, func_EjectSessionClient_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EjectSessionClient`.
 */
moho::CScrLuaInitForm* moho::func_EjectSessionClient_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EjectSessionClient",
    &moho::cfunc_EjectSessionClient,
    nullptr,
    "<global>",
    kEjectSessionClientHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088DF50 (FUN_0088DF50, cfunc_WorldIsLoadingL)
 *
 * What it does:
 * Returns whether the current world frame action is loading or preload.
 */
int moho::cfunc_WorldIsLoadingL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kWorldIsLoadingHelpText, 0, argumentCount);
  }

  const EWldFrameAction frameAction = WLD_GetFrameAction();
  lua_pushboolean(
    state->m_state,
    frameAction == EWldFrameAction::Loading || frameAction == EWldFrameAction::Preload
  );
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088DED0 (FUN_0088DED0, cfunc_WorldIsLoading)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WorldIsLoadingL`.
 */
int moho::cfunc_WorldIsLoading(lua_State* const luaContext)
{
  return cfunc_WorldIsLoadingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088DEF0 (FUN_0088DEF0, func_WorldIsLoading_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `WorldIsLoading`.
 */
moho::CScrLuaInitForm* moho::func_WorldIsLoading_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "WorldIsLoading",
    &moho::cfunc_WorldIsLoading,
    nullptr,
    "<global>",
    kWorldIsLoadingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E030 (FUN_0088E030, cfunc_WorldIsPlayingL)
 *
 * What it does:
 * Returns whether the current world frame action is actively playing.
 */
int moho::cfunc_WorldIsPlayingL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kWorldIsPlayingHelpText, 0, argumentCount);
  }

  lua_pushboolean(state->m_state, WLD_GetFrameAction() == EWldFrameAction::Playing);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088DFB0 (FUN_0088DFB0, cfunc_WorldIsPlaying)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WorldIsPlayingL`.
 */
int moho::cfunc_WorldIsPlaying(lua_State* const luaContext)
{
  return cfunc_WorldIsPlayingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088DFD0 (FUN_0088DFD0, func_WorldIsPlaying_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `WorldIsPlaying`.
 */
moho::CScrLuaInitForm* moho::func_WorldIsPlaying_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "WorldIsPlaying",
    &moho::cfunc_WorldIsPlaying,
    nullptr,
    "<global>",
    kWorldIsPlayingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E260 (FUN_0088E260, cfunc_GetGameSpeedL)
 *
 * What it does:
 * Returns the current requested sim speed from the active client manager.
 */
int moho::cfunc_GetGameSpeedL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameSpeedHelpText, 0, argumentCount);
  }

  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (activeDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  lua_pushnumber(state->m_state, static_cast<float>(clientManager->GetSimRateRequested()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088E1E0 (FUN_0088E1E0, cfunc_GetGameSpeed)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GetGameSpeedL`.
 */
int moho::cfunc_GetGameSpeed(lua_State* const luaContext)
{
  return cfunc_GetGameSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088E200 (FUN_0088E200, func_GetGameSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameSpeed`.
 */
moho::CScrLuaInitForm* moho::func_GetGameSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameSpeed",
    &moho::cfunc_GetGameSpeed,
    nullptr,
    "<global>",
    kGetGameSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E360 (FUN_0088E360, cfunc_SetGameSpeedL)
 *
 * What it does:
 * Validates one requested speed and forwards it to the active client manager.
 */
int moho::cfunc_SetGameSpeedL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetGameSpeedHelpText, 1, argumentCount);
  }

  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (activeDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  if (WLD_CanAdjustSimRate()) {
    CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
    LuaPlus::LuaStackObject speedArg(state, 1);
    if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&speedArg, "integer");
    }

    const int requestedSpeed = static_cast<int>(lua_tonumber(state->m_state, 1));
    clientManager->SetSimRate(requestedSpeed);
  }

  return 0;
}

/**
 * Address: 0x0088E2E0 (FUN_0088E2E0, cfunc_SetGameSpeed)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SetGameSpeedL`.
 */
int moho::cfunc_SetGameSpeed(lua_State* const luaContext)
{
  return cfunc_SetGameSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088E300 (FUN_0088E300, func_SetGameSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetGameSpeed`.
 */
moho::CScrLuaInitForm* moho::func_SetGameSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetGameSpeed",
    &moho::cfunc_SetGameSpeed,
    nullptr,
    "<global>",
    kSetGameSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDEC0 (FUN_008BDEC0, cfunc_AddToSessionExtraSelectListL)
 *
 * What it does:
 * Reads one user-unit Lua object and adds it to world-session extra selection.
 */
int moho::cfunc_AddToSessionExtraSelectListL(LuaPlus::LuaState* const state)
{
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddToSessionExtraSelectListHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
    session->AddToExtraSelectList(userEntity);
  }

  return 0;
}

/**
 * Address: 0x008BDE40 (FUN_008BDE40, cfunc_AddToSessionExtraSelectList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to
 * `cfunc_AddToSessionExtraSelectListL`.
 */
int moho::cfunc_AddToSessionExtraSelectList(lua_State* const luaContext)
{
  return cfunc_AddToSessionExtraSelectListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDE60 (FUN_008BDE60, func_AddToSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `AddToSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_AddToSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddToSessionExtraSelectList",
    &moho::cfunc_AddToSessionExtraSelectList,
    nullptr,
    "<global>",
    kAddToSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDFF0 (FUN_008BDFF0, cfunc_RemoveFromSessionExtraSelectListL)
 *
 * What it does:
 * Reads one user-unit Lua object and removes it from world-session extra
 * selection.
 */
int moho::cfunc_RemoveFromSessionExtraSelectListL(LuaPlus::LuaState* const state)
{
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveFromSessionExtraSelectListHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
    session->RemoveFromExtraSelectList(userEntity);
  }

  return 0;
}

/**
 * Address: 0x008BDF70 (FUN_008BDF70, cfunc_RemoveFromSessionExtraSelectList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to
 * `cfunc_RemoveFromSessionExtraSelectListL`.
 */
int moho::cfunc_RemoveFromSessionExtraSelectList(lua_State* const luaContext)
{
  return cfunc_RemoveFromSessionExtraSelectListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDF90 (FUN_008BDF90, func_RemoveFromSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `RemoveFromSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_RemoveFromSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveFromSessionExtraSelectList",
    &moho::cfunc_RemoveFromSessionExtraSelectList,
    nullptr,
    "<global>",
    kRemoveFromSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE0D0 (FUN_008BE0D0, cfunc_ClearSessionExtraSelectList)
 *
 * What it does:
 * Validates zero-argument call shape and clears the active session extra
 * selection set when a world session exists.
 */
int moho::cfunc_ClearSessionExtraSelectList(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  CWldSession* const activeSession = WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kClearSessionExtraSelectListHelpText, 0, argumentCount);
  }

  activeSession->ClearExtraSelectList();
  return 0;
}

/**
 * Address: 0x008BE120 (FUN_008BE120, func_ClearSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `ClearSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_ClearSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearSessionExtraSelectList",
    &moho::cfunc_ClearSessionExtraSelectList,
    nullptr,
    "<global>",
    kClearSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE1C0 (FUN_008BE1C0, cfunc_CurrentTime)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_CurrentTimeL`.
 */
int moho::cfunc_CurrentTime(lua_State* const luaContext)
{
  return cfunc_CurrentTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE1E0 (FUN_008BE1E0, func_CurrentTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CurrentTime`.
 */
moho::CScrLuaInitForm* moho::func_CurrentTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CurrentTime",
    &moho::cfunc_CurrentTime,
    nullptr,
    "<global>",
    kCurrentTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE240 (FUN_008BE240, cfunc_CurrentTimeL)
 *
 * What it does:
 * Validates zero-argument call shape and returns wall-clock elapsed seconds.
 */
int moho::cfunc_CurrentTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCurrentTimeHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, gpg::time::GetSystemTimer().ElapsedSeconds());
  return 1;
}

/**
 * Address: 0x008BE2A0 (FUN_008BE2A0, cfunc_GameTime)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GameTimeL`.
 */
int moho::cfunc_GameTime(lua_State* const luaContext)
{
  return cfunc_GameTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE2C0 (FUN_008BE2C0, func_GameTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GameTime`.
 */
moho::CScrLuaInitForm* moho::func_GameTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GameTime",
    &moho::cfunc_GameTime,
    nullptr,
    "<global>",
    kGameTimeUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE320 (FUN_008BE320, cfunc_GameTimeL)
 *
 * What it does:
 * Returns current game time in seconds from the active world session.
 */
int moho::cfunc_GameTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGameTimeUserHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  const float gameTimeSeconds = (static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f;
  lua_pushnumber(rawState, gameTimeSeconds);
  return 1;
}

/**
 * Address: 0x008BE3A0 (FUN_008BE3A0, cfunc_GameTick)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GameTickL`.
 */
int moho::cfunc_GameTick(lua_State* const luaContext)
{
  return cfunc_GameTickL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE3C0 (FUN_008BE3C0, func_GameTick_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GameTick`.
 */
moho::CScrLuaInitForm* moho::func_GameTick_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GameTick",
    &moho::cfunc_GameTick,
    nullptr,
    "<global>",
    kGameTickUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE420 (FUN_008BE420, cfunc_GameTickL)
 *
 * What it does:
 * Returns current game time in ticks from the active world session.
 */
int moho::cfunc_GameTickL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGameTickUserHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  lua_pushnumber(rawState, static_cast<float>(session->mGameTick));
  return 1;
}

/**
 * Address: 0x008BE490 (FUN_008BE490, cfunc_IsAllyUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsAllyUserL`.
 */
int moho::cfunc_IsAllyUser(lua_State* const luaContext)
{
  return cfunc_IsAllyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE4B0 (FUN_008BE4B0, func_IsAllyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsAlly`.
 */
moho::CScrLuaInitForm* moho::func_IsAllyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsAlly",
    &moho::cfunc_IsAllyUser,
    nullptr,
    "<global>",
    kIsAllyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE510 (FUN_008BE510, cfunc_IsAllyUserL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as ally.
 */
int moho::cfunc_IsAllyUserL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsAllyUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isAlly = firstArmy != nullptr && secondArmy != nullptr && firstArmy->IsAlly(secondArmy->mArmyIndex);
  lua_pushboolean(rawState, isAlly ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008BE5D0 (FUN_008BE5D0, cfunc_IsEnemyUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsEnemyUserL`.
 */
int moho::cfunc_IsEnemyUser(lua_State* const luaContext)
{
  return cfunc_IsEnemyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE5F0 (FUN_008BE5F0, func_IsEnemyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsEnemy`.
 */
moho::CScrLuaInitForm* moho::func_IsEnemyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsEnemy",
    &moho::cfunc_IsEnemyUser,
    nullptr,
    "<global>",
    kIsEnemyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE650 (FUN_008BE650, cfunc_IsEnemyUserL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as enemy.
 */
int moho::cfunc_IsEnemyUserL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsEnemyUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isEnemy = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->mVarDat.mEnemies.Contains(secondArmy->mArmyIndex);
  lua_pushboolean(rawState, isEnemy ? 1 : 0);
  return 1;
}

namespace
{
  /**
   * Address: 0x00707BF0 (FUN_00707BF0, func_IsNeutral)
   *
   * What it does:
   * Returns whether `targetArmyIndex` is in one neutral-relation bitset lane.
   * Legacy behavior treats `0xFFFFFFFF` as neutral by default.
   */
  [[nodiscard]] bool IsArmyMarkedNeutral(const std::uint32_t targetArmyIndex, const moho::Set& neutralSet) noexcept
  {
    if (targetArmyIndex == std::numeric_limits<std::uint32_t>::max()) {
      return true;
    }

    return neutralSet.Contains(targetArmyIndex);
  }
} // namespace

/**
 * Address: 0x008BE710 (FUN_008BE710, cfunc_IsNeutral)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsNeutralL`.
 */
int moho::cfunc_IsNeutral(lua_State* const luaContext)
{
  return cfunc_IsNeutralL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE730 (FUN_008BE730, func_IsNeutral_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsNeutral`.
 */
moho::CScrLuaInitForm* moho::func_IsNeutral_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsNeutral",
    &moho::cfunc_IsNeutral,
    nullptr,
    "<global>",
    kIsNeutralUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE790 (FUN_008BE790, cfunc_IsNeutralL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as neutral.
 */
int moho::cfunc_IsNeutralL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsNeutralUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr
    && IsArmyMarkedNeutral(secondArmy->mArmyIndex, firstArmy->mVarDat.mNeutrals);
  lua_pushboolean(rawState, isNeutral ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008BE8D0 (FUN_008BE8D0, cfunc_SyncPlayableRectL)
 *
 * What it does:
 * Reads one rect table and synchronizes active-session playable bounds +
 * user-entity visibility against that rectangle.
 */
int moho::cfunc_SyncPlayableRectL(LuaPlus::LuaState* const state)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSyncPlayableRectHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
  const gpg::Rect2i playableRect = SCR_FromLuaCopy<gpg::Rect2<int>>(rectObject);
  session->SyncPlayableRect(playableRect);
  return 0;
}

/**
 * Address: 0x008BE850 (FUN_008BE850, cfunc_SyncPlayableRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SyncPlayableRectL`.
 */
int moho::cfunc_SyncPlayableRect(lua_State* const luaContext)
{
  return cfunc_SyncPlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE870 (FUN_008BE870, func_SyncPlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SyncPlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SyncPlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SyncPlayableRect",
    &moho::cfunc_SyncPlayableRect,
    nullptr,
    "<global>",
    kSyncPlayableRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE980 (FUN_008BE980, cfunc_RandomUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_RandomUserL`.
 */
int moho::cfunc_RandomUser(lua_State* const luaContext)
{
  return cfunc_RandomUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE9A0 (FUN_008BE9A0, func_RandomUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `Random`.
 */
moho::CScrLuaInitForm* moho::func_RandomUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Random",
    &moho::cfunc_RandomUser,
    nullptr,
    "<global>",
    kRandomUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BEA00 (FUN_008BEA00, cfunc_RandomUserL)
 *
 * What it does:
 * Produces one random float or integer range sample from the process-wide
 * random stream for `Random([[min,] max])`.
 */
int moho::cfunc_RandomUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kRandomUserHelpText,
      0,
      2,
      argumentCount
    );
  }

  boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
  if (argumentCount == 0) {
    const double value = static_cast<double>(math_GlobalRandomStream.twister.NextUInt32()) * 2.3283064e-10;
    lua_pushnumber(rawState, value);
    return 1;
  }

  if (argumentCount == 1) {
    const int maxValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
    const std::uint32_t randomValue = math_GlobalRandomStream.twister.NextUInt32();
    const std::uint32_t scaledValue = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(maxValue)) * static_cast<std::uint64_t>(randomValue)) >>
      32u
    );
    const int result = static_cast<int>(scaledValue + 1u);
    lua_pushnumber(rawState, static_cast<float>(result));
    return 1;
  }

  const int minValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
  const int maxValue = LuaPlus::LuaStackObject(state, 2).GetInteger();
  const std::uint32_t randomValue = math_GlobalRandomStream.twister.NextUInt32();
  const std::uint32_t span = (static_cast<std::uint32_t>(maxValue) + 1u) - static_cast<std::uint32_t>(minValue);
  const std::uint32_t scaledOffset =
    static_cast<std::uint32_t>((static_cast<std::uint64_t>(span) * static_cast<std::uint64_t>(randomValue)) >> 32u);
  const int result = static_cast<int>(static_cast<std::uint32_t>(minValue) + scaledOffset);
  lua_pushnumber(rawState, static_cast<float>(result));
  return 1;
}

/**
 * Address: 0x008B9D10 (FUN_008B9D10, cfunc_EntityCategoryContainsUserL)
 *
 * What it does:
 * Tests whether arg#1 category set contains arg#2 unit/blueprint category.
 */
int moho::cfunc_EntityCategoryContainsUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryContainsUserHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryContainsUserNoSessionText);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  const LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));
  const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);

  const bool contains =
    categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  lua_pushboolean(rawState, contains ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008B9C90 (FUN_008B9C90, cfunc_EntityCategoryContainsUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsUserL`.
 */
int moho::cfunc_EntityCategoryContainsUser(lua_State* const luaContext)
{
  return cfunc_EntityCategoryContainsUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9CB0 (FUN_008B9CB0, func_EntityCategoryContainsUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `EntityCategoryContains`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryContainsUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EntityCategoryContains",
    &moho::cfunc_EntityCategoryContainsUser,
    nullptr,
    "<global>",
    kEntityCategoryContainsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008B9F70 (FUN_008B9F70, cfunc_EntityCategoryFilterDownUserL)
 *
 * What it does:
 * Filters arg#2 values into a result table by keeping entries whose resolved
 * unit blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterDownUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryFilterDownUserHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterDownUserNoSessionText);
  }

  if (lua_type(rawState, 1) == 0 || lua_type(rawState, 2) == 0) {
    return 0;
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);
  if (!categorySet) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterDownUserInvalidCategoryText);
  }

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);
    if (!blueprint) {
      continue;
    }

    if (categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.Insert(resultIndex, valueObject);
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9EF0 (FUN_008B9EF0, cfunc_EntityCategoryFilterDownUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownUserL`.
 */
int moho::cfunc_EntityCategoryFilterDownUser(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterDownUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9F10 (FUN_008B9F10, func_EntityCategoryFilterDownUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterDownUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EntityCategoryFilterDown",
    &moho::cfunc_EntityCategoryFilterDownUser,
    nullptr,
    "<global>",
    kEntityCategoryFilterDownUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA2A0 (FUN_008BA2A0, cfunc_EntityCategoryFilterOutL)
 *
 * What it does:
 * Filters arg#2 values into a result table by excluding entries whose resolved
 * unit blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterOutL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryFilterOutHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterOutNoSessionText);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);
  if (!categorySet) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterOutInvalidCategoryText);
  }

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];

    const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);
    if (!blueprint) {
      continue;
    }

    if (!categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.Insert(resultIndex, valueObject);
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BA220 (FUN_008BA220, cfunc_EntityCategoryFilterOut)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterOutL`.
 */
int moho::cfunc_EntityCategoryFilterOut(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterOutL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA240 (FUN_008BA240, func_EntityCategoryFilterOut_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterOut`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterOut_LuaFuncDef()
{
  // User, not Sim. The binary links this one into scr_UserInits
  // (FUN_008BA240) - the UI reads it while the front end comes up, and the
  // Sim set is not run against the user Lua state at all.
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EntityCategoryFilterOut",
    &moho::cfunc_EntityCategoryFilterOut,
    nullptr,
    "<global>",
    kEntityCategoryFilterOutHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA540 (FUN_008BA540, cfunc_ExecLuaInSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_ExecLuaInSimL`.
 */
int moho::cfunc_ExecLuaInSim(lua_State* const luaContext)
{
  return cfunc_ExecLuaInSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA560 (FUN_008BA560, func_ExecLuaInSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExecLuaInSim`.
 */
moho::CScrLuaInitForm* moho::func_ExecLuaInSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ExecLuaInSim",
    &moho::cfunc_ExecLuaInSim,
    nullptr,
    "<global>",
    kExecLuaInSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA5C0 (FUN_008BA5C0, cfunc_ExecLuaInSimL)
 *
 * What it does:
 * Reads `(functionName,args)` from Lua and forwards one
 * `ExecuteLuaInSim(functionName,args)` request through the active sim driver.
 */
int moho::cfunc_ExecLuaInSimL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kExecLuaInSimHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject functionNameArg(state, 1);
  const char* functionNameText = lua_tostring(state->m_state, 1);
  if (!functionNameText) {
    LuaPlus::LuaStackObject::TypeError(&functionNameArg, "string");
    functionNameText = "";
  }

  const std::string functionName(functionNameText);
  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
    LuaPlus::LuaObject callbackArgs(LuaPlus::LuaStackObject(state, 2));
    activeDriver->ExecuteLuaInSim(functionName.c_str(), callbackArgs);
  }
  return 0;
}

/**
 * Address: 0x008BA770 (FUN_008BA770, cfunc_SimCallbackL)
 *
 * What it does:
 * Reads callback payload (`Func`,`Args`) and optional selection forwarding
 * flag, then marshals `CMDST_LuaSimCallback` through the active sim driver.
 */
int moho::cfunc_SimCallbackL(LuaPlus::LuaState* const state)
{
  if (IsLuaCallbackDispatchBlocked() || !state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kSimCallbackHelpText,
      1,
      2,
      argumentCount
    );
  }

  lua_settop(rawState, 2);

  lua_pushstring(rawState, "Func");
  lua_gettable(rawState, 1);
  const int callbackNameIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject callbackNameArg(state, callbackNameIndex);

  const char* callbackNameText = lua_tostring(rawState, callbackNameIndex);
  if (!callbackNameText) {
    LuaPlus::LuaStackObject::TypeError(&callbackNameArg, "string");
    callbackNameText = "";
  }
  const msvc8::string callbackName(callbackNameText);

  lua_pushstring(rawState, "Args");
  lua_gettable(rawState, 1);
  LuaPlus::LuaObject callbackArgs(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));

  LuaPlus::LuaStackObject includeSelectionArg(state, 2);
  BVSet<EntId, EntIdUniverse> selectedEntities{};

  if (LuaPlus::LuaStackObject::GetBoolean(&includeSelectionArg)) {
    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      msvc8::vector<UserUnit*> selectedUnits{};
      session->GetSelectionUnits(selectedUnits);
      for (UserUnit* const selectedUnit : selectedUnits) {
        IUnit* const iunitBridge = ResolveIUnitBridge(selectedUnit);
        if (!iunitBridge) {
          continue;
        }

        selectedEntities.Bits().Add(static_cast<unsigned int>(iunitBridge->GetEntityId()));
      }
    }
  }

  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
    activeDriver->LuaSimCallback(callbackName.c_str(), callbackArgs, selectedEntities);
  }
  return 0;
}

/**
 * Address: 0x008BA6F0 (FUN_008BA6F0, cfunc_SimCallback)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SimCallbackL`.
 */
int moho::cfunc_SimCallback(lua_State* const luaContext)
{
  return cfunc_SimCallbackL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA710 (FUN_008BA710, func_SimCallback_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SimCallback`.
 */
moho::CScrLuaInitForm* moho::func_SimCallback_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SimCallback",
    &moho::cfunc_SimCallback,
    nullptr,
    "<global>",
    kSimCallbackHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BADE0 (FUN_008BADE0, cfunc_SetAutoModeL)
 *
 * What it does:
 * Reads `(unitTable, enabled)` and emits one `SetAutoMode` info-pair per
 * live user-unit entry.
 */
int moho::cfunc_SetAutoModeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAutoModeHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject enabledArg(state, 2);
  const bool enabled = LuaPlus::LuaStackObject::GetBoolean(&enabledArg);

  if (!unitListObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitListObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (!iunitBridge || iunitBridge->IsDead()) {
      continue;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      const auto entityIdWord = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iunitBridge->GetEntityId()));
      activeDriver->ProcessInfoPair(
        reinterpret_cast<void*>(entityIdWord),
        "SetAutoMode",
        enabled ? "true" : "false"
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BAD60 (FUN_008BAD60, cfunc_SetAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetAutoModeL`.
 */
int moho::cfunc_SetAutoMode(lua_State* const luaContext)
{
  return cfunc_SetAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAD80 (FUN_008BAD80, func_SetAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder for `SetAutoMode`.
 */
moho::CScrLuaInitForm* moho::func_UnitSetAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetAutoMode",
    &moho::cfunc_SetAutoMode,
    nullptr,
    "<global>",
    kSetAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB360 (FUN_008BB360, cfunc_SetAutoSurfaceModeL)
 *
 * What it does:
 * Reads `(unitTable, enabled)` and emits one `SetAutoSurfaceMode` info-pair
 * per live user-unit entry.
 */
int moho::cfunc_SetAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAutoSurfaceModeHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject enabledArg(state, 2);
  const bool enabled = LuaPlus::LuaStackObject::GetBoolean(&enabledArg);

  if (!unitListObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitListObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (!iunitBridge || iunitBridge->IsDead()) {
      continue;
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      const auto entityIdWord = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iunitBridge->GetEntityId()));
      activeDriver->ProcessInfoPair(
        reinterpret_cast<void*>(entityIdWord),
        "SetAutoSurfaceMode",
        enabled ? "true" : "false"
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BB2E0 (FUN_008BB2E0, cfunc_SetAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetAutoSurfaceModeL`.
 */
int moho::cfunc_SetAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_SetAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB300 (FUN_008BB300, func_SetAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SetAutoSurfaceMode`.
 */
moho::CScrLuaInitForm* moho::func_SetAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetAutoSurfaceMode",
    &moho::cfunc_SetAutoSurfaceMode,
    nullptr,
    "<global>",
    kSetAutoSurfaceModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBE60 (FUN_008BBE60, cfunc_ToggleScriptBitL)
 *
 * What it does:
 * Reads `(unitTable, bit, currentState)` and emits `ToggleScriptBit`
 * info-pairs for live units whose toggle-cap lane exposes that bit and whose
 * current script-bit value matches `currentState`.
 */
int moho::cfunc_ToggleScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kToggleScriptBitExpectedArgsText, 3, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));

  LuaPlus::LuaStackObject bitArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    bitArg.TypeError("integer");
  }
  const int bitIndex = static_cast<int>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject currentStateArg(state, 3);
  const bool currentState = currentStateArg.GetBoolean();

  char bitText[0x10]{};
  std::snprintf(bitText, sizeof(bitText), "%d", bitIndex);

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead()) {
        continue;
      }

      const std::uint32_t toggleCapMask = 1u << (static_cast<std::uint32_t>(bitIndex) & 0x1Fu);
      if ((iunitBridge->GetAttributes().toggleCapsMask & toggleCapMask) == 0u) {
        continue;
      }

      const bool scriptBitStateMatches =
        (GetUserUnitScriptBitMask(userUnit) & BuildScriptBitMask(bitIndex)) != 0;
      if (scriptBitStateMatches != currentState) {
        continue;
      }

      if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
        const auto entityIdWord = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iunitBridge->GetEntityId()));
        activeDriver->ProcessInfoPair(reinterpret_cast<void*>(entityIdWord), "ToggleScriptBit", bitText);
      }
    }
  }

  return 0;
}

/**
 * Address: 0x008BBDE0 (FUN_008BBDE0, cfunc_ToggleScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_ToggleScriptBitL`.
 */
int moho::cfunc_ToggleScriptBit(lua_State* const luaContext)
{
  return cfunc_ToggleScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BBE00 (FUN_008BBE00, func_ToggleScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `ToggleScriptBit`.
 */
moho::CScrLuaInitForm* moho::func_ToggleScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ToggleScriptBit",
    &moho::cfunc_ToggleScriptBit,
    nullptr,
    "<global>",
    kToggleScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC100 (FUN_008BC100, cfunc_SetPausedL)
 *
 * What it does:
 * Reads `(unitTable, paused)` and emits one `SetPaused` info-pair per live
 * user-unit entry while callback dispatch remains enabled.
 */
int moho::cfunc_SetPausedL(LuaPlus::LuaState* const state)
{
  if (IsLuaCallbackDispatchBlocked()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetPausedHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject pausedArg(state, 2);
  const bool paused = pausedArg.GetBoolean();

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead()) {
        continue;
      }

      if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
        const auto entityIdWord = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(iunitBridge->GetEntityId()));
        activeDriver->ProcessInfoPair(
          reinterpret_cast<void*>(entityIdWord),
          "SetPaused",
          paused ? "true" : "false"
        );
      }
    }
  }

  return 0;
}

/**
 * Address: 0x008BC080 (FUN_008BC080, cfunc_SetPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetPausedL`.
 */
int moho::cfunc_SetPaused(lua_State* const luaContext)
{
  return cfunc_SetPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC0A0 (FUN_008BC0A0, func_SetPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SetPaused`.
 */
moho::CScrLuaInitForm* moho::func_SetPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetPaused",
    &moho::cfunc_SetPaused,
    nullptr,
    "<global>",
    kSetPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC280 (FUN_008BC280, cfunc_GetAttachedUnitsList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to `cfunc_GetAttachedUnitsListL`.
 */
int moho::cfunc_GetAttachedUnitsList(lua_State* const luaContext)
{
  return cfunc_GetAttachedUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC2A0 (FUN_008BC2A0, func_GetAttachedUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetAttachedUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_GetAttachedUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAttachedUnitsList",
    &moho::cfunc_GetAttachedUnitsList,
    nullptr,
    "<global>",
    kGetAttachedUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC300 (FUN_008BC300, cfunc_GetAttachedUnitsListL)
 *
 * What it does:
 * Builds one Lua table containing alive attached user-unit script objects for
 * each source unit in the input table.
 */
int moho::cfunc_GetAttachedUnitsListL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession() || state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAttachedUnitsListHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0);

  if (unitListObject.IsTable()) {
    int resultIndex = 1;
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject sourceUnitObject = unitListObject[unitIndex];
      UserUnit* const sourceUnit = SCR_FromLua_UserUnit(sourceUnitObject, state);
      IUnit* const sourceUnitBridge = ResolveIUnitBridge(sourceUnit);
      if (sourceUnitBridge == nullptr || sourceUnitBridge->IsDead()) {
        continue;
      }

      UserEntity* const sourceEntity = reinterpret_cast<UserEntity*>(sourceUnit);
      CWldSession* const session = sourceEntity->mSession;
      if (session == nullptr) {
        continue;
      }

      const SSTIInlineUIntVector& attachedIdList = sourceEntity->mVariableData.mAuxValueVector;
      if (attachedIdList.mBegin == nullptr || attachedIdList.mEnd == nullptr || attachedIdList.mEnd < attachedIdList.mBegin) {
        continue;
      }

      for (const std::uint32_t* attachedIdIt = attachedIdList.mBegin; attachedIdIt < attachedIdList.mEnd; ++attachedIdIt) {
        UserEntity* const attachedEntity = FindUserSessionEntityById(session, static_cast<std::int32_t>(*attachedIdIt));
        if (attachedEntity == nullptr || attachedEntity->mVariableData.mIsDead != 0u) {
          continue;
        }

        UserUnit* const attachedUnit = attachedEntity->IsUserUnit();
        IUnit* const attachedUnitBridge = ResolveIUnitBridge(attachedUnit);
        if (attachedUnitBridge == nullptr) {
          continue;
        }

        LuaPlus::LuaObject attachedUnitObject = attachedUnitBridge->GetLuaObject();
        resultObject.SetObject(resultIndex, attachedUnitObject);
        ++resultIndex;
      }
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BC5F0 (FUN_008BC5F0, cfunc_ValidateUnitsListL)
 *
 * What it does:
 * Filters one input unit table down to alive, non-destroy-queued unit Lua
 * objects and returns the filtered table.
 */
int moho::cfunc_ValidateUnitsListL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kValidateUnitsListHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0);

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    int resultIndex = 1;
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitListObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      LuaPlus::LuaObject unitLuaObject = iunitBridge->GetLuaObject();
      resultObject.SetObject(resultIndex, unitLuaObject);
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BC570 (FUN_008BC570, cfunc_ValidateUnitsList)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to
 * `cfunc_ValidateUnitsListL`.
 */
int moho::cfunc_ValidateUnitsList(lua_State* const luaContext)
{
  return cfunc_ValidateUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC590 (FUN_008BC590, func_ValidateUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `ValidateUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_ValidateUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ValidateUnitsList",
    &moho::cfunc_ValidateUnitsList,
    nullptr,
    "<global>",
    kValidateUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC7A0 (FUN_008BC7A0, cfunc_GetAssistingUnitsList)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_GetAssistingUnitsListL`.
 */
int moho::cfunc_GetAssistingUnitsList(lua_State* const luaContext)
{
  return cfunc_GetAssistingUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC7C0 (FUN_008BC7C0, func_GetAssistingUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetAssistingUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_GetAssistingUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAssistingUnitsList",
    &moho::cfunc_GetAssistingUnitsList,
    nullptr,
    "<global>",
    kGetAssistingUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC820 (FUN_008BC820, cfunc_GetAssistingUnitsListL)
 *
 * What it does:
 * Returns one Lua array of focused-army pod units that are assisting one of
 * the input units (or the unit itself when matching POD filters).
 */
int moho::cfunc_GetAssistingUnitsListL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->mRules == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAssistingUnitsListHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0u);

  const CategoryWordRangeView* const podStagingCategoryRange = session->mRules->GetEntityCategory("PODSTAGINGPLATFORM");
  const CategoryWordRangeView* const podCategoryRange = session->mRules->GetEntityCategory("POD");
  const EntityCategorySet* const podStagingCategory =
    podStagingCategoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(podStagingCategoryRange) : nullptr;
  const EntityCategorySet* const podCategory =
    podCategoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(podCategoryRange) : nullptr;
  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  if (!sourceUnitsObject.IsTable() || podCategory == nullptr || focusArmy == nullptr) {
    resultTable.PushStack(state);
    return 1;
  }

  std::set<UserUnit*> emittedUnits{};
  std::int32_t resultIndex = 1;
  const UserSessionEntityMapView& entityMap = GetUserSessionEntityMapView(session);

  const int sourceCount = sourceUnitsObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject sourceObject = sourceUnitsObject[sourceIndex];
    UserUnit* const sourceUnit = ResolveUserUnitOptional(sourceObject, state);
    IUnit* const sourceBridge = ResolveIUnitBridge(sourceUnit);
    if (sourceBridge == nullptr || sourceBridge->IsDead() || sourceUnit->IsBeingBuilt()) {
      continue;
    }

    const REntityBlueprint* const sourceBlueprint = sourceBridge->GetBlueprint();
    const bool sourceIsPodStaging =
      (podStagingCategory != nullptr) && (sourceBlueprint != nullptr)
      && EntityCategory::HasBlueprint(sourceBlueprint, podStagingCategory);
    const bool sourceIsPod =
      (sourceBlueprint != nullptr) && EntityCategory::HasBlueprint(sourceBlueprint, podCategory);
    if (!sourceIsPodStaging && !sourceIsPod) {
      continue;
    }

    for (UserSessionEntityMapNodeView* node = UserSessionEntityMapFirstNode(entityMap);
         node != nullptr && node != entityMap.head;
         node = UserSessionEntityMapNextNode(node, entityMap.head)) {
      UserEntity* const entity = node->value;
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const candidateUnit = entity->IsUserUnit();
      IUnit* const candidateBridge = ResolveIUnitBridge(candidateUnit);
      if (candidateBridge == nullptr || candidateBridge->IsDead() || candidateUnit->IsBeingBuilt()) {
        continue;
      }

      UserEntity* const candidateEntity = reinterpret_cast<UserEntity*>(candidateUnit);
      if (candidateEntity->mArmy != focusArmy) {
        continue;
      }

      const REntityBlueprint* const candidateBlueprint = candidateBridge->GetBlueprint();
      if (candidateBlueprint == nullptr || !EntityCategory::HasBlueprint(candidateBlueprint, podCategory)) {
        continue;
      }

      const UserUnit* const assistTarget = ResolveAssistTargetUnit(candidateUnit);
      if (candidateUnit != sourceUnit && assistTarget != sourceUnit) {
        continue;
      }

      if (!emittedUnits.insert(candidateUnit).second) {
        continue;
      }

      LuaPlus::LuaObject unitObject = candidateBridge->GetLuaObject();
      resultTable.SetObject(resultIndex, unitObject);
      ++resultIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BCC30 (FUN_008BCC30, cfunc_GetArmyAvatars)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmyAvatarsL`.
 */
int moho::cfunc_GetArmyAvatars(lua_State* const luaContext)
{
  return cfunc_GetArmyAvatarsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BCC50 (FUN_008BCC50, func_GetArmyAvatars_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetArmyAvatars`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyAvatars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetArmyAvatars",
    &moho::cfunc_GetArmyAvatars,
    nullptr,
    "<global>",
    kGetArmyAvatarsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BCCB0 (FUN_008BCCB0, cfunc_GetArmyAvatarsL)
 *
 * What it does:
 * Returns one Lua array of focus-army avatar unit script objects.
 */
int moho::cfunc_GetArmyAvatarsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  UserArmy* const focusArmy = ResolveFocusArmy(session);
  if (focusArmy == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyAvatarsHelpText, 0, argumentCount);
  }

  const UserArmyAvatarVectorRuntimeView& avatarRefs = ResolveArmyAvatarVectorView(focusArmy);

  if (avatarRefs.begin == nullptr || avatarRefs.end == nullptr || avatarRefs.end <= avatarRefs.begin) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const int tableCapacity = static_cast<int>(avatarRefs.end - avatarRefs.begin);
  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, tableCapacity, 0u);

  std::int32_t luaIndex = 1;
  for (const UserEntityWeakRefRuntimeView* weakRef = avatarRefs.begin; weakRef < avatarRefs.end; ++weakRef) {
    AppendEntityUnitLuaObject(resultTable, luaIndex, DecodeLinkedUserEntity(*weakRef));
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BCE70 (FUN_008BCE70, cfunc_GetIdleEngineers)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetIdleEngineersL`.
 */
int moho::cfunc_GetIdleEngineers(lua_State* const luaContext)
{
  return cfunc_GetIdleEngineersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BCE90 (FUN_008BCE90, func_GetIdleEngineers_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetIdleEngineers`.
 */
moho::CScrLuaInitForm* moho::func_GetIdleEngineers_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetIdleEngineers",
    &moho::cfunc_GetIdleEngineers,
    nullptr,
    "<global>",
    kGetIdleEngineersHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BCEF0 (FUN_008BCEF0, cfunc_GetIdleEngineersL)
 *
 * What it does:
 * Returns one Lua array of focus-army idle engineer unit script objects.
 */
int moho::cfunc_GetIdleEngineersL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  UserArmy* const focusArmy = ResolveFocusArmy(session);
  if (focusArmy == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIdleEngineersHelpText, 0, argumentCount);
  }

  UserEntityWeakSetRuntimeView* const idleSet = ResolveIdleUnitSetView(focusArmy, false);
  const int liveUnitCount = CountLiveUserEntityWeakSetEntriesAndPrune(idleSet);
  if (idleSet == nullptr || idleSet->head == nullptr || liveUnitCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, liveUnitCount, 0u);

  std::int32_t luaIndex = 1;
  for (UserEntityWeakSetNodeRuntimeView* node = WeakSetFirstNode(*idleSet);
       node != nullptr && node != idleSet->head;
       node = WeakSetNextNode(node, idleSet->head)) {
    AppendEntityUnitLuaObject(resultTable, luaIndex, DecodeLinkedUserEntity(node->weakEntityLink));
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD100 (FUN_008BD100, cfunc_GetIdleFactories)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetIdleFactoriesL`.
 */
int moho::cfunc_GetIdleFactories(lua_State* const luaContext)
{
  return cfunc_GetIdleFactoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD120 (FUN_008BD120, func_GetIdleFactories_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetIdleFactories`.
 */
moho::CScrLuaInitForm* moho::func_GetIdleFactories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetIdleFactories",
    &moho::cfunc_GetIdleFactories,
    nullptr,
    "<global>",
    kGetIdleFactoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD180 (FUN_008BD180, cfunc_GetIdleFactoriesL)
 *
 * What it does:
 * Returns one Lua array of focus-army idle factory unit script objects.
 */
int moho::cfunc_GetIdleFactoriesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  UserArmy* const focusArmy = ResolveFocusArmy(session);
  if (focusArmy == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIdleFactoriesHelpText, 0, argumentCount);
  }

  UserEntityWeakSetRuntimeView* const idleSet = ResolveIdleUnitSetView(focusArmy, true);
  const int liveUnitCount = CountLiveUserEntityWeakSetEntriesAndPrune(idleSet);
  if (idleSet == nullptr || idleSet->head == nullptr || liveUnitCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, liveUnitCount, 0u);

  std::int32_t luaIndex = 1;
  for (UserEntityWeakSetNodeRuntimeView* node = WeakSetFirstNode(*idleSet);
       node != nullptr && node != idleSet->head;
       node = WeakSetNextNode(node, idleSet->head)) {
    AppendEntityUnitLuaObject(resultTable, luaIndex, DecodeLinkedUserEntity(node->weakEntityLink));
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD680 (FUN_008BD680, cfunc_GetSelectedUnitsL)
 *
 * What it does:
 * Builds and returns a Lua array containing currently selected unit script objects.
 */
int moho::cfunc_GetSelectedUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSelectedUnitsHelpText, 0, argumentCount);
  }

  msvc8::vector<UserUnit*> selectedUnits{};
  session->GetSelectionUnits(selectedUnits);
  if (selectedUnits.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(selectedUnits.size()), 0u);

  std::int32_t resultIndex = 1;
  for (UserUnit* const selectedUnit : selectedUnits) {
    IUnit* const iunitBridge = ResolveIUnitBridge(selectedUnit);
    if (!iunitBridge) {
      continue;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(resultIndex, unitObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD600 (FUN_008BD600, cfunc_GetSelectedUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSelectedUnitsL`.
 */
int moho::cfunc_GetSelectedUnits(lua_State* const luaContext)
{
  return cfunc_GetSelectedUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD620 (FUN_008BD620, func_GetSelectedUnits_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `GetSelectedUnits`.
 */
moho::CScrLuaInitForm* moho::func_GetSelectedUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSelectedUnits",
    &moho::cfunc_GetSelectedUnits,
    nullptr,
    "<global>",
    kGetSelectedUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD410 (FUN_008BD410, cfunc_GetValidAttackingUnitsL)
 *
 * IDA signature:
 * int __cdecl cfunc_GetValidAttackingUnitsL(LuaPlus::LuaState *state);
 *
 * What it does:
 * Builds and returns a Lua array of the currently-selected units that can attack
 * the hovered target (via `CWldSession::GetValidAttackingUnits`), each as its
 * script object. Returns nil when the set is empty.
 */
int moho::cfunc_GetValidAttackingUnitsL(LuaPlus::LuaState* const state)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetValidAttackingUnitsHelpText, 0, argumentCount);
  }

  msvc8::vector<UserUnit*> validUnits{};
  session->GetValidAttackingUnits(validUnits);
  if (validUnits.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(validUnits.size()), 0u);

  std::int32_t resultIndex = 1;
  for (UserUnit* const validUnit : validUnits) {
    IUnit* const iunitBridge = ResolveIUnitBridge(validUnit);
    if (!iunitBridge) {
      continue;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(resultIndex, unitObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD5C0 (FUN_008BD5C0, cfunc_GetValidAttackingUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetValidAttackingUnitsL`.
 */
int moho::cfunc_GetValidAttackingUnits(lua_State* const luaContext)
{
  return cfunc_GetValidAttackingUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD3B0 (FUN_008BD3B0, func_GetValidAttackingUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane global Lua binder form for `GetValidAttackingUnits`.
 */
moho::CScrLuaInitForm* moho::func_GetValidAttackingUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetValidAttackingUnits",
    &moho::cfunc_GetValidAttackingUnits,
    nullptr,
    "<global>",
    kGetValidAttackingUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD870 (FUN_008BD870, cfunc_SelectUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SelectUnitsL`.
 */
int moho::cfunc_SelectUnits(lua_State* const luaContext)
{
  return cfunc_SelectUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD890 (FUN_008BD890, func_SelectUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SelectUnits`.
 */
moho::CScrLuaInitForm* moho::func_SelectUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SelectUnits",
    &moho::cfunc_SelectUnits,
    nullptr,
    "<global>",
    kSelectUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD8F0 (FUN_008BD8F0, cfunc_SelectUnitsL)
 *
 * What it does:
 * Builds one validated selection set from Lua input units, applies it to the
 * world session, and returns a Lua array of accepted unit objects.
 */
int moho::cfunc_SelectUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSelectUnitsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0u);

  msvc8::vector<UserUnit*> selectionUnits{};
  std::int32_t resultIndex = 1;
  if (sourceUnitsObject.IsTable()) {
    const int unitCount = sourceUnitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = sourceUnitsObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
      if (userEntity != nullptr && userEntity->IsSelectable()) {
        AppendSelectionUnitUnique(selectionUnits, userUnit);
      } else if (UserUnit* const attachmentParent = ResolveSelectableTransportAttachmentParent(userUnit);
                 attachmentParent != nullptr) {
        AppendSelectionUnitUnique(selectionUnits, attachmentParent);
      }

      LuaPlus::LuaObject selectedUnitObject = iunitBridge->GetLuaObject();
      resultTable.SetObject(resultIndex, selectedUnitObject);
      ++resultIndex;
    }
  }

  session->SetSelectionUnits(selectionUnits);
  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BDC30 (FUN_008BDC30, cfunc_AddSelectUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_AddSelectUnitsL`.
 */
int moho::cfunc_AddSelectUnits(lua_State* const luaContext)
{
  return cfunc_AddSelectUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDC50 (FUN_008BDC50, func_AddSelectUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `AddSelectUnits`.
 */
moho::CScrLuaInitForm* moho::func_AddSelectUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddSelectUnits",
    &moho::cfunc_AddSelectUnits,
    nullptr,
    "<global>",
    kAddSelectUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDCB0 (FUN_008BDCB0, cfunc_AddSelectUnitsL)
 *
 * What it does:
 * Adds validated selectable units from Lua input to current selection and
 * applies the merged set back into the world session.
 */
int moho::cfunc_AddSelectUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddSelectUnitsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  msvc8::vector<UserUnit*> mergedSelection{};
  session->GetSelectionUnits(mergedSelection);

  if (sourceUnitsObject.IsTable()) {
    const int unitCount = sourceUnitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = sourceUnitsObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
      if (userEntity == nullptr || !userEntity->IsSelectable()) {
        continue;
      }
      AppendSelectionUnitUnique(mergedSelection, userUnit);
    }
  }

  session->SetSelectionUnits(mergedSelection);
  return 0;
}

/**
 * Address: 0x0083F000 (FUN_0083F000, func_EngineStartSplashScreens)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and starts splash-screen UI.
 */
int moho::func_EngineStartSplashScreens(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEngineStartSplashScreensHelpText, 0, argumentCount);
  }

  UI_StartSplashScreens();
  return 0;
}

/**
 * Address: 0x0083F040 (FUN_0083F040, func_EngineStartSplashScreens_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EngineStartSplashScreens`.
 */
moho::CScrLuaInitForm* moho::func_EngineStartSplashScreens_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EngineStartSplashScreens",
    &moho::func_EngineStartSplashScreens,
    nullptr,
    "<global>",
    kEngineStartSplashScreensHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F0E0 (FUN_0083F0E0, cfunc_EngineStartFrontEndUI)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and starts front-end UI.
 */
int moho::cfunc_EngineStartFrontEndUI(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEngineStartFrontEndUIHelpText, 0, argumentCount);
  }

  UI_StartFrontEnd();
  return 0;
}

/**
 * Address: 0x0083F120 (FUN_0083F120, func_EngineStartFrontEndUI_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EngineStartFrontEndUI`.
 */
moho::CScrLuaInitForm* moho::func_EngineStartFrontEndUI_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EngineStartFrontEndUI",
    &moho::cfunc_EngineStartFrontEndUI,
    nullptr,
    "<global>",
    kEngineStartFrontEndUIHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F1C0 (FUN_0083F1C0, cfunc_ExitApplication)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and requests app shutdown.
 */
int moho::cfunc_ExitApplication(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kExitApplicationHelpText, 0, argumentCount);
  }

  wxTheApp->ExitMainLoop();
  return 0;
}

/**
 * Address: 0x0083F210 (FUN_0083F210, func_ExitApplication_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExitApplication`.
 */
moho::CScrLuaInitForm* moho::func_ExitApplication_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ExitApplication",
    &moho::cfunc_ExitApplication,
    nullptr,
    "<global>",
    kExitApplicationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F2B0 (FUN_0083F2B0, cfunc_ExitGame)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and requests sim exit.
 */
int moho::cfunc_ExitGame(lua_State* const luaContext)
{
  return cfunc_ExitGameL(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x0083F360 (FUN_0083F360, sub_83F360)
 *
 * What it does:
 * Validates zero args and requests world-frame action `Exit`.
 */
int moho::cfunc_ExitGameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kExitGameHelpText, 0, argumentCount);
  }

  if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
    WLD_SetFrameAction(EWldFrameAction::Exit);
  }

  return 0;
}

/**
 * Address: 0x0083F300 (FUN_0083F300, func_ExitGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExitGame`.
 */
moho::CScrLuaInitForm* moho::func_ExitGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ExitGame",
    &moho::cfunc_ExitGame,
    nullptr,
    "<global>",
    kExitGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F3A0 (FUN_0083F3A0, cfunc_RestartSession)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_RestartSessionL`.
 */
int moho::cfunc_RestartSession(lua_State* const luaContext)
{
  return cfunc_RestartSessionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F3C0 (FUN_0083F3C0, func_RestartSession_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RestartSession`.
 */
moho::CScrLuaInitForm* moho::func_RestartSession_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RestartSession",
    &moho::cfunc_RestartSession,
    nullptr,
    "<global>",
    kRestartSessionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F420 (FUN_0083F420, cfunc_RestartSessionL)
 *
 * What it does:
 * Validates zero arguments and requests world-frame action `CreateSession`
 * when restart prerequisites are present.
 */
int moho::cfunc_RestartSessionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRestartSessionHelpText, 0, argumentCount);
  }

  if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
    CWldSession* const session = WLD_GetActiveSession();
    if (session != nullptr && session->mLaunchInfo.get() != nullptr) {
      WLD_SetFrameAction(EWldFrameAction::CreateSession);
    }
  }

  return 0;
}

/**
 * Address: 0x0083F470 (FUN_0083F470, cfunc_GetFrame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetFrameL`.
 */
int moho::cfunc_GetFrame(lua_State* const luaContext)
{
  return cfunc_GetFrameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F490 (FUN_0083F490, func_GetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetFrame`.
 */
moho::CScrLuaInitForm* moho::func_GetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFrame",
    &moho::cfunc_GetFrame,
    nullptr,
    "<global>",
    kGetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F4F0 (FUN_0083F4F0, cfunc_GetFrameL)
 *
 * What it does:
 * Resolves one root UI frame index and pushes the corresponding Lua frame
 * object when it belongs to the same root Lua state.
 */
int moho::cfunc_GetFrameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFrameHelpText, 1, argumentCount);
  }

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr || !uiManager->HasFrames()) {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
    return 1;
  }

  LuaPlus::LuaStackObject headArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    headArg.TypeError("number");
  }

  const int frameHead = static_cast<int>(lua_tonumber(rawState, 1));
  if (frameHead < 0 || static_cast<std::size_t>(frameHead) >= uiManager->mFrames.Size()) {
    return 0;
  }

  CMauiFrame* const frame = uiManager->mFrames[static_cast<std::size_t>(frameHead)].get();
  if (frame == nullptr) {
    return 0;
  }

  const CMauiControlLuaObjectView* const frameView = CMauiControlLuaObjectView::FromControl(frame);
  if (frameView->luaObject.m_state != state->m_rootState) {
    return 0;
  }

  frameView->luaObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F5D0 (FUN_0083F5D0, cfunc_ClearFrame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_ClearFrameL`.
 */
int moho::cfunc_ClearFrame(lua_State* const luaContext)
{
  return cfunc_ClearFrameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F5F0 (FUN_0083F5F0, func_ClearFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ClearFrame`.
 */
moho::CScrLuaInitForm* moho::func_ClearFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearFrame",
    &moho::cfunc_ClearFrame,
    nullptr,
    "<global>",
    kClearFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F650 (FUN_0083F650, cfunc_ClearFrameL)
 *
 * What it does:
 * Clears one frame by index or all frames when the optional argument is nil.
 */
int moho::cfunc_ClearFrameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount >= 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kClearFrameHelpText,
      0,
      1,
      argumentCount
    );
  }

  lua_settop(rawState, 1);

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr || !uiManager->HasFrames()) {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
    return 0;
  }

  int frameHead = -1;
  if (lua_type(rawState, 1) != LUA_TNIL) {
    LuaPlus::LuaStackObject headArg(state, 1);
    frameHead = static_cast<int>(headArg.ToNumber());
  }

  uiManager->ClearChildren(frameHead);
  return 0;
}

/**
 * Address: 0x0083F700 (FUN_0083F700, cfunc_GetNumRootFrames)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetNumRootFramesL`.
 */
int moho::cfunc_GetNumRootFrames(lua_State* const luaContext)
{
  return cfunc_GetNumRootFramesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F720 (FUN_0083F720, func_GetNumRootFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetNumRootFrames`.
 */
moho::CScrLuaInitForm* moho::func_GetNumRootFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetNumRootFrames",
    &moho::cfunc_GetNumRootFrames,
    nullptr,
    "<global>",
    kGetNumRootFramesHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F780 (FUN_0083F780, cfunc_GetNumRootFramesL)
 *
 * What it does:
 * Pushes the current root-frame count as a Lua number.
 */
int moho::cfunc_GetNumRootFramesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetNumRootFramesHelpText, 0, argumentCount);
  }

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager != nullptr && uiManager->HasFrames()) {
    lua_pushnumber(rawState, static_cast<float>(uiManager->mFrames.Size()));
    (void)lua_gettop(rawState);
  } else {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
  }

  return 1;
}

/**
 * Address: 0x0083F880 (FUN_0083F880, cfunc_GetEconomyTotalsL)
 *
 * What it does:
 * Builds and returns one table containing focus-army economy totals.
 */
int moho::cfunc_GetEconomyTotalsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetEconomyTotalsHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    gpg::Warnf(kGetEconomyTotalsMissingSessionWarning);
    return 0;
  }

  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  const SEconTotals zeroTotals{};
  const SEconTotals& totals = focusArmy ? focusArmy->mVarDat.mEconomyTotals : zeroTotals;

  LuaPlus::LuaObject stored(state);
  stored.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject income(state);
  income.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject reclaimed(state);
  reclaimed.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject lastUseRequested(state);
  lastUseRequested.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject lastUseActual(state);
  lastUseActual.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject maxStorage(state);
  maxStorage.AssignNewTable(state, 2, 0u);

  constexpr std::array<const char*, 2> kResourceLexical = {"ENERGY", "MASS"};
  const std::array<float, 2> storedValues = {totals.mStored.ENERGY, totals.mStored.MASS};
  const std::array<float, 2> incomeValues = {totals.mIncome.ENERGY, totals.mIncome.MASS};
  const std::array<float, 2> reclaimedValues = {totals.mReclaimed.ENERGY, totals.mReclaimed.MASS};
  const std::array<float, 2> requestedValues = {totals.mLastUseRequested.ENERGY, totals.mLastUseRequested.MASS};
  const std::array<float, 2> actualValues = {totals.mLastUseActual.ENERGY, totals.mLastUseActual.MASS};
  const std::array<std::uint32_t, 2> storageValues = {
    static_cast<std::uint32_t>(totals.mMaxStorage.ENERGY),
    static_cast<std::uint32_t>(totals.mMaxStorage.MASS)
  };

  for (std::size_t resourceIndex = 0; resourceIndex < kResourceLexical.size(); ++resourceIndex) {
    const char* const key = kResourceLexical[resourceIndex];
    stored.SetNumber(key, storedValues[resourceIndex]);
    income.SetNumber(key, incomeValues[resourceIndex]);
    reclaimed.SetNumber(key, reclaimedValues[resourceIndex]);
    lastUseRequested.SetNumber(key, requestedValues[resourceIndex]);
    lastUseActual.SetNumber(key, actualValues[resourceIndex]);
    maxStorage.SetInteger(key, static_cast<std::int32_t>(storageValues[resourceIndex]));
  }

  LuaPlus::LuaObject totalsTable(state);
  totalsTable.AssignNewTable(state, 6, 0u);
  totalsTable.SetObject("stored", stored);
  totalsTable.SetObject("income", income);
  totalsTable.SetObject("reclaimed", reclaimed);
  totalsTable.SetObject("lastUseRequested", lastUseRequested);
  totalsTable.SetObject("lastUseActual", lastUseActual);
  totalsTable.SetObject("maxStorage", maxStorage);

  totalsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F800 (FUN_0083F800, cfunc_GetEconomyTotals)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetEconomyTotalsL`.
 */
int moho::cfunc_GetEconomyTotals(lua_State* const luaContext)
{
  return cfunc_GetEconomyTotalsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F820 (FUN_0083F820, func_GetEconomyTotals_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetEconomyTotals`.
 */
moho::CScrLuaInitForm* moho::func_GetEconomyTotals_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetEconomyTotals",
    &moho::cfunc_GetEconomyTotals,
    nullptr,
    "<global>",
    kGetEconomyTotalsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083FED0 (FUN_0083FED0, cfunc_GetResourceSharing)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetResourceSharingL`.
 */
int moho::cfunc_GetResourceSharing(lua_State* const luaContext)
{
  return cfunc_GetResourceSharingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083FEF0 (FUN_0083FEF0, func_GetResourceSharing_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetResourceSharing`.
 */
moho::CScrLuaInitForm* moho::func_GetResourceSharing_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetResourceSharing",
    &moho::cfunc_GetResourceSharing,
    nullptr,
    "<global>",
    kGetResourceSharingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083FF50 (FUN_0083FF50, cfunc_GetResourceSharingL)
 *
 * What it does:
 * Pushes whether the focused user army has resource sharing enabled.
 */
int moho::cfunc_GetResourceSharingL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetResourceSharingHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    gpg::Warnf(kGetEconomyTotalsMissingSessionWarning);
    return 0;
  }

  bool isResourceSharingEnabled = false;
  const int focusArmyIndex = session->FocusArmy;
  if (focusArmyIndex >= 0) {
    const std::size_t armyIndex = static_cast<std::size_t>(focusArmyIndex);
    if (armyIndex < session->userArmies.size()) {
      const UserArmy* const focusedArmy = session->userArmies[armyIndex];
      if (focusedArmy != nullptr && focusedArmy->mVarDat.mIsResourceSharingEnabled != 0u) {
        isResourceSharingEnabled = true;
      }
    }
  }

  lua_pushboolean(rawState, isResourceSharingEnabled ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008420A0 (FUN_008420A0, cfunc_GetCurrentUIState)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetCurrentUIStateL`.
 */
int moho::cfunc_GetCurrentUIState(lua_State* const luaContext)
{
  return cfunc_GetCurrentUIStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008420C0 (FUN_008420C0, func_GetCurrentUIState_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetCurrentUIState`.
 */
moho::CScrLuaInitForm* moho::func_GetCurrentUIState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCurrentUIState",
    &moho::cfunc_GetCurrentUIState,
    nullptr,
    "<global>",
    kGetCurrentUIStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842120 (FUN_00842120, cfunc_GetCurrentUIStateL)
 *
 * What it does:
 * Pushes current UI-state lexical value (`splash`, `frontend`, or `game`).
 */
int moho::cfunc_GetCurrentUIStateL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCurrentUIStateHelpText, 0, argumentCount);
  }

  gpg::RRef currentUiStateRef{};
  gpg::RRef::CurrentUIState(&currentUiStateRef);
  const msvc8::string lexical = currentUiStateRef.GetLexical();
  lua_pushstring(rawState, lexical.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0083FFE0 (FUN_0083FFE0, cfunc_GetSimTicksPerSecond)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSimTicksPerSecondL`.
 */
int moho::cfunc_GetSimTicksPerSecond(lua_State* const luaContext)
{
  return cfunc_GetSimTicksPerSecondL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00840000 (FUN_00840000, func_GetSimTicksPerSecond_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSimTicksPerSecond`.
 */
moho::CScrLuaInitForm* moho::func_GetSimTicksPerSecond_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSimTicksPerSecond",
    &moho::cfunc_GetSimTicksPerSecond,
    nullptr,
    "<global>",
    kGetSimTicksPerSecondHelpText
  );
  return &binder;
}

/**
 * Address: 0x00840060 (FUN_00840060, cfunc_GetSimTicksPerSecondL)
 *
 * What it does:
 * Pushes fixed simulation ticks-per-second (10.0) as a Lua number.
 */
int moho::cfunc_GetSimTicksPerSecondL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSimTicksPerSecondHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, 10.0);
  return 1;
}

/**
 * Address: 0x00897780 (FUN_00897780, cfunc_SessionRequestPause)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionRequestPauseL`.
 */
int moho::cfunc_SessionRequestPause(lua_State* const luaContext)
{
  return cfunc_SessionRequestPauseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008977A0 (FUN_008977A0, func_SessionRequestPause_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionRequestPause`.
 */
moho::CScrLuaInitForm* moho::func_SessionRequestPause_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionRequestPause",
    &moho::cfunc_SessionRequestPause,
    nullptr,
    "<global>",
    kSessionRequestPauseHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897800 (FUN_00897800, cfunc_SessionRequestPauseL)
 *
 * What it does:
 * Requests world-session pause from Lua after validating active session.
 */
int moho::cfunc_SessionRequestPauseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionRequestPauseHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionRequestPauseNoActiveSessionText);
  }

  session->RequestPause();
  return 0;
}

/**
 * Address: 0x00897850 (FUN_00897850, cfunc_SessionResume)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionResumeL`.
 */
int moho::cfunc_SessionResume(lua_State* const luaContext)
{
  return cfunc_SessionResumeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897870 (FUN_00897870, func_SessionResume_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionResume`.
 */
moho::CScrLuaInitForm* moho::func_SessionResume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionResume",
    &moho::cfunc_SessionResume,
    nullptr,
    "<global>",
    kSessionResumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008978D0 (FUN_008978D0, cfunc_SessionResumeL)
 *
 * What it does:
 * Requests world-session resume from Lua after validating active session.
 */
int moho::cfunc_SessionResumeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionResumeHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionResumeNoActiveSessionText);
  }

  session->Resume();
  return 0;
}

/**
 * Address: 0x00897920 (FUN_00897920, cfunc_SessionIsPaused)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsPausedL`.
 */
int moho::cfunc_SessionIsPaused(lua_State* const luaContext)
{
  return cfunc_SessionIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897940 (FUN_00897940, func_SessionIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsPaused`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsPaused",
    &moho::cfunc_SessionIsPaused,
    nullptr,
    "<global>",
    kSessionIsPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008979A0 (FUN_008979A0, cfunc_SessionIsPausedL)
 *
 * What it does:
 * Pushes pause state from replay/requested/non-local session lanes.
 */
int moho::cfunc_SessionIsPausedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionIsPausedNoActiveSessionText);
  }

  std::uint8_t isPaused = 0;
  if (session->IsReplay) {
    isPaused = session->mReplayIsPaused;
  } else if (session->mRequestingPauseState != 0u) {
    isPaused = session->mRequestingPause;
  } else {
    isPaused = session->mSessionPauseStateA;
  }

  lua_pushboolean(state->m_state, isPaused != 0u ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897A00 (FUN_00897A00, cfunc_SessionIsGameOver)
 *
 * What it does:
 * Pushes whether the active world-session game-over flag is set.
 */
int moho::cfunc_SessionIsGameOver(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionIsGameOverNoActiveSessionText);
  }

  lua_pushboolean(state->m_state, session->IsGameOver != 0u ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897A50 (FUN_00897A50, func_SessionIsGameOver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsGameOver`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsGameOver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsGameOver",
    &moho::cfunc_SessionIsGameOver,
    nullptr,
    "<global>",
    kSessionIsGameOverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897C70 (FUN_00897C70, cfunc_SessionGetLocalCommandSource)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionGetLocalCommandSourceL`.
 */
int moho::cfunc_SessionGetLocalCommandSource(lua_State* const luaContext)
{
  return cfunc_SessionGetLocalCommandSourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897C90 (FUN_00897C90, func_SessionGetLocalCommandSource_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionGetLocalCommandSource`.
 */
moho::CScrLuaInitForm* moho::func_SessionGetLocalCommandSource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionGetLocalCommandSource",
    &moho::cfunc_SessionGetLocalCommandSource,
    nullptr,
    "<global>",
    kSessionGetLocalCommandSourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897CF0 (FUN_00897CF0, cfunc_SessionGetLocalCommandSourceL)
 *
 * What it does:
 * Returns one-based local command-source id (`0` when unavailable).
 */
int moho::cfunc_SessionGetLocalCommandSourceL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionGetLocalCommandSourceHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetLocalCommandSourceNoActiveSessionText);
  }

  int localCommandSource = session->ourCmdSource;
  if (localCommandSource == static_cast<int>(kInvalidCommandSource)) {
    localCommandSource = 0;
  } else {
    ++localCommandSource;
  }

  lua_pushnumber(rawState, static_cast<float>(localCommandSource));
  return 1;
}

/**
 * Address: 0x00897D70 (FUN_00897D70, cfunc_SessionIsReplayUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsReplayUserL`.
 */
int moho::cfunc_SessionIsReplayUser(lua_State* const luaContext)
{
  return cfunc_SessionIsReplayUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897D90 (FUN_00897D90, func_SessionIsReplayUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsReplay`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsReplayUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsReplay",
    &moho::cfunc_SessionIsReplayUser,
    nullptr,
    "<global>",
    kSessionIsReplayUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897DF0 (FUN_00897DF0, cfunc_SessionIsReplayUserL)
 *
 * What it does:
 * Pushes whether the active world-session is replay-backed.
 */
int moho::cfunc_SessionIsReplayUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsReplayUserHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsReplay ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897E60 (FUN_00897E60, cfunc_SessionIsBeingRecorded)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionIsBeingRecordedL`.
 */
int moho::cfunc_SessionIsBeingRecorded(lua_State* const luaContext)
{
  return cfunc_SessionIsBeingRecordedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897E80 (FUN_00897E80, func_SessionIsBeingRecorded_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsBeingRecorded`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsBeingRecorded_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsBeingRecorded",
    &moho::cfunc_SessionIsBeingRecorded,
    nullptr,
    "<global>",
    kSessionIsBeingRecordedHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897EE0 (FUN_00897EE0, cfunc_SessionIsBeingRecordedL)
 *
 * What it does:
 * Pushes whether the active world-session is currently being recorded.
 */
int moho::cfunc_SessionIsBeingRecordedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsBeingRecordedHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsBeingRecorded ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897F50 (FUN_00897F50, cfunc_SessionIsMultiplayer)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsMultiplayerL`.
 */
int moho::cfunc_SessionIsMultiplayer(lua_State* const luaContext)
{
  return cfunc_SessionIsMultiplayerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897F70 (FUN_00897F70, func_SessionIsMultiplayer_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsMultiplayer`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsMultiplayer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsMultiplayer",
    &moho::cfunc_SessionIsMultiplayer,
    nullptr,
    "<global>",
    kSessionIsMultiplayerHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897FD0 (FUN_00897FD0, cfunc_SessionIsMultiplayerL)
 *
 * What it does:
 * Pushes whether the active world-session is multiplayer.
 */
int moho::cfunc_SessionIsMultiplayerL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsMultiplayerHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsMultiplayer ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898040 (FUN_00898040, cfunc_SessionIsObservingAllowed)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionIsObservingAllowedL`.
 */
int moho::cfunc_SessionIsObservingAllowed(lua_State* const luaContext)
{
  return cfunc_SessionIsObservingAllowedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898060 (FUN_00898060, func_SessionIsObservingAllowed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsObservingAllowed`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsObservingAllowed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsObservingAllowed",
    &moho::cfunc_SessionIsObservingAllowed,
    nullptr,
    "<global>",
    kSessionIsObservingAllowedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008980C0 (FUN_008980C0, cfunc_SessionIsObservingAllowedL)
 *
 * What it does:
 * Pushes whether observing is enabled for the active world-session.
 */
int moho::cfunc_SessionIsObservingAllowedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsObservingAllowedHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsObservingAllowed ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898130 (FUN_00898130, cfunc_SessionCanRestart)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionCanRestartL`.
 */
int moho::cfunc_SessionCanRestart(lua_State* const luaContext)
{
  return cfunc_SessionCanRestartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898150 (FUN_00898150, func_SessionCanRestart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionCanRestart`.
 */
moho::CScrLuaInitForm* moho::func_SessionCanRestart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionCanRestart",
    &moho::cfunc_SessionCanRestart,
    nullptr,
    "<global>",
    kSessionCanRestartHelpText
  );
  return &binder;
}

/**
 * Address: 0x008981B0 (FUN_008981B0, cfunc_SessionCanRestartL)
 *
 * What it does:
 * Pushes whether restart launch metadata exists for the active session.
 */
int moho::cfunc_SessionCanRestartL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionCanRestartHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->mLaunchInfo.get() != nullptr ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898220 (FUN_00898220, cfunc_SessionIsActive)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsActiveL`.
 */
int moho::cfunc_SessionIsActive(lua_State* const luaContext)
{
  return cfunc_SessionIsActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898240 (FUN_00898240, func_SessionIsActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsActive`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsActive",
    &moho::cfunc_SessionIsActive,
    nullptr,
    "<global>",
    kSessionIsActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x008982A0 (FUN_008982A0, cfunc_SessionIsActiveL)
 *
 * What it does:
 * Pushes whether any world-session is currently active.
 */
int moho::cfunc_SessionIsActiveL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsActiveHelpText, 0, argumentCount);
  }

  lua_pushboolean(rawState, WLD_GetActiveSession() != nullptr ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008982F0 (FUN_008982F0, cfunc_SessionGetScenarioInfo)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionGetScenarioInfoL`.
 */
int moho::cfunc_SessionGetScenarioInfo(lua_State* const luaContext)
{
  return cfunc_SessionGetScenarioInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898310 (FUN_00898310, func_SessionGetScenarioInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionGetScenarioInfo`.
 */
moho::CScrLuaInitForm* moho::func_SessionGetScenarioInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionGetScenarioInfo",
    &moho::cfunc_SessionGetScenarioInfo,
    nullptr,
    "<global>",
    kSessionGetScenarioInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x00898370 (FUN_00898370, cfunc_SessionGetScenarioInfoL)
 *
 * What it does:
 * Validates user-lua state ownership and pushes the active session
 * `ScenarioInfo` table.
 */
int moho::cfunc_SessionGetScenarioInfoL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionGetScenarioInfoHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  if (state->m_rootState != session->mState) {
    LuaPlus::LuaState::Error(state, kWrongLuaStateText);
  }

  const LuaPlus::LuaObject scenarioInfo = session->GetScenarioInfo();
  scenarioInfo.PushStack(state);
  return 1;
}

/**
 * Address: 0x00842BB0 (FUN_00842BB0, cfunc_GetMouseWorldPos)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetMouseWorldPosL`.
 */
int moho::cfunc_GetMouseWorldPos(lua_State* const luaContext)
{
  return cfunc_GetMouseWorldPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842BD0 (FUN_00842BD0, func_GetMouseWorldPosUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetMouseWorldPos`.
 */
moho::CScrLuaInitForm* moho::func_GetMouseWorldPosUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMouseWorldPos",
    &moho::cfunc_GetMouseWorldPos,
    nullptr,
    "<global>",
    kGetMouseWorldPosUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842C30 (FUN_00842C30, cfunc_GetMouseWorldPosL)
 *
 * What it does:
 * Pushes current world-space mouse position as one Lua vector.
 */
int moho::cfunc_GetMouseWorldPosL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetMouseWorldPosUserHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  const LuaPlus::LuaObject worldPositionObject = SCR_ToLua<Wm3::Vector3<float>>(state, session->CursorWorldPos);
  worldPositionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00842D10 (FUN_00842D10, cfunc_GetMouseScreenPos)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetMouseScreenPosL`.
 */
int moho::cfunc_GetMouseScreenPos(lua_State* const luaContext)
{
  return cfunc_GetMouseScreenPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842D30 (FUN_00842D30, func_GetMouseScreenPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetMouseScreenPos`.
 */
moho::CScrLuaInitForm* moho::func_GetMouseScreenPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMouseScreenPos",
    &moho::cfunc_GetMouseScreenPos,
    nullptr,
    "<global>",
    kGetMouseScreenPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842D90 (FUN_00842D90, cfunc_GetMouseScreenPosL)
 *
 * What it does:
 * Pushes current screen-space mouse position as one Lua vector.
 */
int moho::cfunc_GetMouseScreenPosL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetMouseScreenPosHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  const LuaPlus::LuaObject screenPositionObject = SCR_ToLua<Wm3::Vector2<float>>(state, session->CursorScreenPos);
  screenPositionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00842E60 (FUN_00842E60, cfunc_SetFocusArmyUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SetFocusArmyUserL`.
 */
int moho::cfunc_SetFocusArmyUser(lua_State* const luaContext)
{
  return cfunc_SetFocusArmyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842E80 (FUN_00842E80, func_SetFocusArmyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetFocusArmy`.
 */
moho::CScrLuaInitForm* moho::func_SetFocusArmyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFocusArmy",
    &moho::cfunc_SetFocusArmyUser,
    nullptr,
    "<global>",
    kSetFocusArmyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842EE0 (FUN_00842EE0, cfunc_SetFocusArmyUserL)
 *
 * What it does:
 * Validates one-based army index input and requests focus-army update.
 */
int moho::cfunc_SetFocusArmyUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetFocusArmyUserHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  LuaPlus::LuaStackObject indexArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }

  int focusArmyIndex = static_cast<int>(lua_tonumber(rawState, 1));
  if (focusArmyIndex != -1) {
    const int maxArmyIndexOneBased = static_cast<int>(session->userArmies.size());
    if (focusArmyIndex < 1 || focusArmyIndex > maxArmyIndexOneBased) {
      LuaPlus::LuaState::Error(
        state,
        "Invalid army index of %d; must be between 1 and %d inclusive.",
        focusArmyIndex,
        maxArmyIndexOneBased
      );
    }

    --focusArmyIndex;
  }

  session->RequestFocusArmy(focusArmyIndex);
  return 0;
}

/**
 * Address: 0x00842FD0 (FUN_00842FD0, cfunc_GetFocusArmyUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetFocusArmyUserL`.
 */
int moho::cfunc_GetFocusArmyUser(lua_State* const luaContext)
{
  return cfunc_GetFocusArmyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842FF0 (FUN_00842FF0, func_GetFocusArmyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetFocusArmy`.
 */
moho::CScrLuaInitForm* moho::func_GetFocusArmyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFocusArmy",
    &moho::cfunc_GetFocusArmyUser,
    nullptr,
    "<global>",
    kGetFocusArmyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843050 (FUN_00843050, cfunc_GetFocusArmyUserL)
 *
 * What it does:
 * Pushes the focused army as a one-based Lua index (`-1` when unset).
 */
int moho::cfunc_GetFocusArmyUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFocusArmyUserHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  int focusArmy = session->FocusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }

  lua_pushnumber(rawState, static_cast<float>(focusArmy));
  return 1;
}

/**
 * Address: 0x008430D0 (FUN_008430D0, cfunc_IsObserver)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_IsObserverL`.
 */
int moho::cfunc_IsObserver(lua_State* const luaContext)
{
  return cfunc_IsObserverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008430F0 (FUN_008430F0, func_IsObserver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsObserver`.
 */
moho::CScrLuaInitForm* moho::func_IsObserver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsObserver",
    &moho::cfunc_IsObserver,
    nullptr,
    "<global>",
    kIsObserverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843150 (FUN_00843150, cfunc_IsObserverL)
 *
 * What it does:
 * Pushes whether the active focus army has no owning `UserArmy` entry.
 */
int moho::cfunc_IsObserverL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsObserverHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  UserArmy* focusArmy = nullptr;
  const int focusArmyIndex = session->FocusArmy;
  if (focusArmyIndex >= 0) {
    focusArmy = session->userArmies[static_cast<std::size_t>(focusArmyIndex)];
  }

  lua_pushboolean(rawState, focusArmy == nullptr);
  return 1;
}

/**
 * Address: 0x008431D0 (FUN_008431D0, cfunc_GetGameTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeL`.
 */
int moho::cfunc_GetGameTime(lua_State* const luaContext)
{
  return cfunc_GetGameTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008431F0 (FUN_008431F0, func_GetGameTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameTime`.
 */
moho::CScrLuaInitForm* moho::func_GetGameTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameTime",
    &moho::cfunc_GetGameTime,
    nullptr,
    "<global>",
    kGetGameTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843250 (FUN_00843250, cfunc_GetGameTimeL)
 *
 * What it does:
 * Formats active-session simulation time as `HH:MM:SS` and returns one Lua
 * string result.
 */
int moho::cfunc_GetGameTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameTimeHelpText, 0, argumentCount);
  }

  CWldSession* session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
    session = WLD_GetActiveSession();
    if (!session) {
      LuaPlus::LuaState::Error(state, kNoActiveSessionText);
    }
  }

  const int wholeSeconds = static_cast<int>((static_cast<double>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1);
  const auto signedSeconds = static_cast<long long>(wholeSeconds);
  const bool isNegative = signedSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(signedSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(signedSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x00843380 (FUN_00843380, cfunc_GetGameTimeSecondsUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeSecondsUserL`.
 */
int moho::cfunc_GetGameTimeSecondsUser(lua_State* const luaContext)
{
  return cfunc_GetGameTimeSecondsUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008433A0 (FUN_008433A0, func_GetGameTimeSecondsUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameTimeSeconds`.
 */
moho::CScrLuaInitForm* moho::func_GetGameTimeSecondsUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameTimeSeconds",
    &moho::cfunc_GetGameTimeSecondsUser,
    nullptr,
    "<global>",
    kGetGameTimeSecondsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843400 (FUN_00843400, cfunc_GetGameTimeSecondsUserL)
 *
 * What it does:
 * Pushes active-session elapsed game time in seconds as a Lua number.
 */
int moho::cfunc_GetGameTimeSecondsUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameTimeSecondsUserHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  const float gameTimeSeconds = (static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f;
  lua_pushnumber(rawState, gameTimeSeconds);
  return 1;
}

/**
 * Address: 0x00843480 (FUN_00843480, cfunc_GetSystemTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeL`.
 */
int moho::cfunc_GetSystemTime(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008434A0 (FUN_008434A0, func_GetSystemTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSystemTime`.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSystemTime",
    &moho::cfunc_GetSystemTime,
    nullptr,
    "<global>",
    kGetSystemTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843500 (FUN_00843500, cfunc_GetSystemTimeL)
 *
 * What it does:
 * Formats process-system elapsed seconds as `HH:MM:SS` and returns one Lua
 * string result.
 */
int moho::cfunc_GetSystemTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSystemTimeHelpText, 0, argumentCount);
  }

  const auto totalSeconds = static_cast<long long>(gpg::time::GetSystemTimer().ElapsedSeconds());
  const bool isNegative = totalSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(totalSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(totalSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x008435F4 (FUN_008435F4)
 * Address: 0x008365B4 (FUN_008365B4)
 *
 * What it does:
 * Normalizes Lua callback entry calling convention and forwards to
 * `cfunc_GetSystemTimeSecondsL`.
 */
static int cfunc_GetSystemTimeSecondsDispatch(lua_State* const luaContext)
{
  return moho::cfunc_GetSystemTimeSecondsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008435F0 (FUN_008435F0, cfunc_GetSystemTimeSeconds)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeSecondsL`.
 */
int moho::cfunc_GetSystemTimeSeconds(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeSecondsDispatch(luaContext);
}

/**
 * Address: 0x00843610 (FUN_00843610, func_GetSystemTimeSeconds_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSystemTimeSeconds`.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTimeSeconds_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSystemTimeSeconds",
    &moho::cfunc_GetSystemTimeSeconds,
    nullptr,
    "<global>",
    kGetSystemTimeSecondsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843670 (FUN_00843670, cfunc_GetSystemTimeSecondsL)
 *
 * What it does:
 * Pushes process-system elapsed time in seconds as a Lua number.
 */
int moho::cfunc_GetSystemTimeSecondsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSystemTimeSecondsHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, gpg::time::GetSystemTimer().ElapsedSeconds());
  return 1;
}

/**
 * Address: 0x00843750 (FUN_00843750, cfunc_FormatTimeL)
 *
 * What it does:
 * Validates one numeric seconds argument and returns a formatted `HH:MM:SS`
 * text value for Lua scripts.
 */
int moho::cfunc_FormatTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kFormatTimeHelpText, 1, argumentCount);
  }

  if (!WLD_GetActiveSession()) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  LuaPlus::LuaStackObject secondsArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&secondsArg, "number");
  }

  const auto totalSeconds = static_cast<long long>(lua_tonumber(rawState, 1));
  const bool isNegative = totalSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(totalSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(totalSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x008436D0 (FUN_008436D0, cfunc_FormatTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_FormatTimeL`.
 */
int moho::cfunc_FormatTime(lua_State* const luaContext)
{
  return cfunc_FormatTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008436F0 (FUN_008436F0, func_FormatTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `FormatTime`.
 */
moho::CScrLuaInitForm* moho::func_FormatTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "FormatTime",
    &moho::cfunc_FormatTime,
    nullptr,
    "<global>",
    kFormatTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008438A0 (FUN_008438A0, cfunc_GetSimRate)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSimRateL`.
 */
int moho::cfunc_GetSimRate(lua_State* const luaContext)
{
  return cfunc_GetSimRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008438C0 (FUN_008438C0, func_GetSimRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSimRate`.
 */
moho::CScrLuaInitForm* moho::func_GetSimRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSimRate",
    &moho::cfunc_GetSimRate,
    nullptr,
    "<global>",
    kGetSimRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843920 (FUN_00843920, cfunc_GetSimRateL)
 *
 * What it does:
 * Pushes the current client-manager simulation rate as a Lua number.
 */
int moho::cfunc_GetSimRateL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSimRateHelpText, 0, argumentCount);
  }

  if (!WLD_GetActiveSession()) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  lua_pushnumber(rawState, static_cast<float>(clientManager->GetSimRate()));
  return 1;
}

/**
 * Address: 0x008439A0 (FUN_008439A0, cfunc_GetArmiesTable)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmiesTableL`.
 */
int moho::cfunc_GetArmiesTable(lua_State* const luaContext)
{
  return cfunc_GetArmiesTableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008439C0 (FUN_008439C0, func_GetArmiesTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmiesTable`.
 */
moho::CScrLuaInitForm* moho::func_GetArmiesTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetArmiesTable",
    &moho::cfunc_GetArmiesTable,
    nullptr,
    "<global>",
    kGetArmiesTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x008485C0 (FUN_008485C0)
 *
 * What it does:
 * Copies one `UserArmy*` vector lane into caller scratch storage for stable
 * iteration during Lua table materialization.
 */
static msvc8::vector<moho::UserArmy*>* SnapshotUserArmyVector(
  const msvc8::vector<moho::UserArmy*>& source,
  msvc8::vector<moho::UserArmy*>* const outSnapshot
)
{
  if (outSnapshot == nullptr) {
    return nullptr;
  }

  *outSnapshot = source;
  return outSnapshot;
}

/**
 * Address: 0x00843A20 (FUN_00843A20, cfunc_GetArmiesTableL)
 *
 * What it does:
 * Builds and returns one Lua table describing session armies and command
 * source authorization lanes.
 */
int moho::cfunc_GetArmiesTableL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmiesTableHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  msvc8::vector<UserArmy*> armiesSnapshot{};
  SnapshotUserArmyVector(session->userArmies, &armiesSnapshot);
  const msvc8::vector<UserArmy*>& armies = armiesSnapshot;
  const std::size_t armyCount = armies.size();

  LuaPlus::LuaObject result(state);
  result.AssignNewTable(state, 0, 0u);
  result.SetInteger("numArmies", static_cast<std::int32_t>(armyCount));

  int focusArmy = session->FocusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }
  result.SetInteger("focusArmy", focusArmy);

  LuaPlus::LuaObject armiesTable(state);
  armiesTable.AssignNewTable(state, static_cast<int>(armyCount), 0u);

  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    UserArmy* const army = armies[armyIndex];

    LuaPlus::LuaObject armyEntry(state);
    armyEntry.AssignNewTable(state, 0, 0u);
    armyEntry.SetString("name", army->mArmyName.c_str());
    armyEntry.SetString("nickname", army->mPlayerName.c_str());
    armyEntry.SetInteger("faction", army->mVarDat.mFaction);

    const LuaPlus::LuaObject playerColor = SCR_EncodeColor(state, army->mVarDat.mPlayerColorBgra);
    armyEntry.SetObject("color", playerColor);

    const LuaPlus::LuaObject iconColor = SCR_EncodeColor(state, army->mVarDat.mArmyColorBgra);
    armyEntry.SetObject("iconColor", iconColor);

    armyEntry.SetBoolean("showScore", army->mVarDat.mShowScore != 0u);
    armyEntry.SetBoolean("civilian", army->mIsCivilian != 0u);
    armyEntry.SetBoolean("human", gpg::STR_CompareNoCase(army->mVarDat.mArmyType.c_str(), "human") == 0);
    armyEntry.SetBoolean("outOfGame", army->mVarDat.mIsOutOfGame != 0u);

    LuaPlus::LuaObject authorizedCommandSources(state);
    authorizedCommandSources.AssignNewTable(state, 0, 0u);
    const Set& validSources = army->mVarDat.mValidCommandSources;
    int luaSourceIndex = 1;
    const std::size_t usedWords = static_cast<std::size_t>(validSources.items_end - validSources.items_begin);
    for (std::size_t wordIndex = 0; wordIndex < usedWords; ++wordIndex) {
      const std::uint32_t wordBits = validSources.items_begin[wordIndex];
      if (wordBits == 0u) {
        continue;
      }

      for (std::uint32_t bit = 0; bit < 32u; ++bit) {
        if ((wordBits & (1u << bit)) == 0u) {
          continue;
        }
        const std::uint32_t sourceId =
          static_cast<std::uint32_t>((validSources.baseWordIndex + static_cast<std::int32_t>(wordIndex)) * 32u + bit);
        authorizedCommandSources.SetInteger(luaSourceIndex++, static_cast<std::int32_t>(sourceId + 1u));
      }
    }

    armyEntry.SetObject("authorizedCommandSources", authorizedCommandSources);
    armiesTable.SetObject(static_cast<std::int32_t>(armyIndex + 1u), armyEntry);
  }

  result.SetObject("armiesTable", armiesTable);
  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x00843E50 (FUN_00843E50, cfunc_GetArmyScore)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmyScoreL`.
 */
int moho::cfunc_GetArmyScore(lua_State* const luaContext)
{
  return cfunc_GetArmyScoreL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00843E70 (FUN_00843E70, func_GetArmyScore_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyScore`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyScore_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetArmyScore",
    &moho::cfunc_GetArmyScore,
    nullptr,
    "<global>",
    kGetArmyScoreHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843ED0 (FUN_00843ED0, cfunc_GetArmyScoreL)
 *
 * What it does:
 * Validates one argument and active-session precondition for the
 * `GetArmyScore` global Lua callback lane.
 */
int moho::cfunc_GetArmyScoreL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyScoreHelpText, 1, argumentCount);
  }

  if (WLD_GetActiveSession() == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  return 0;
}

/**
 * Address: 0x00843F20 (FUN_00843F20, cfunc_DeleteCommand)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_DeleteCommandL`.
 */
int moho::cfunc_DeleteCommand(lua_State* const luaContext)
{
  return cfunc_DeleteCommandL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00843F40 (FUN_00843F40, func_DeleteCommand_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `DeleteCommand`.
 */
moho::CScrLuaInitForm* moho::func_DeleteCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DeleteCommand",
    &moho::cfunc_DeleteCommand,
    nullptr,
    "<global>",
    kDeleteCommandHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843FA0 (FUN_00843FA0, cfunc_DeleteCommandL)
 *
 * What it does:
 * Looks up one command issue helper by Lua command id and marshals one
 * `DecreaseCommandCount` request through the active sim driver, then records
 * one local helper queue update for the same command id/count delta.
 */
int moho::cfunc_DeleteCommandL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDeleteCommandHelpText, 1, argumentCount);
  }

  const CmdId commandId = ReadLuaCommandIdArg(state, 1);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  CommandIssueHelperRuntimeView* const commandIssue = FindCommandIssueHelper(session, commandId);
  if (!commandIssue) {
    return 0;
  }

  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
    // The driver marshals the decrement and returns the resulting command
    // cookie; the event is queued with that cookie (FUN_00843FA0 passes the
    // DecreaseCommandCount result, not the input command id).
    const CmdId resultCookie = activeDriver->DecreaseCommandCount(commandIssue->commandId, 1);
    QueueCommandIssueDecreaseCountEvent(*commandIssue, resultCookie, 1);
  }

  return 0;
}

/**
 * Address: 0x00836980 (FUN_00836980, cfunc_DecreaseBuildCountInQueueL)
 *
 * IDA signature:
 * int __usercall cfunc_DecreaseBuildCountInQueueL@<eax>(LuaPlus::LuaState *a1@<eax>);
 *
 * What it does:
 * Lua worker for `DecreaseBuildCountInQueue(queueIndex, count)`. Reads the
 * 1-based factory build-queue item index and a decrement count, then walks that
 * item's queued command ids from the most recently queued command backward. For
 * each command still tracked by a live command-issue helper it marshals a
 * `DecreaseCommandCount` through the active sim driver (clamped to the helper's
 * remaining effective build count) and records the matching local decrease-count
 * update event, stopping once the requested count has been fully consumed.
 */
int moho::cfunc_DecreaseBuildCountInQueueL(LuaPlus::LuaState* const state)
{
  constexpr const char* kDecreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDecreaseBuildCountInQueueHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  LuaPlus::LuaStackObject queueIndexArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&queueIndexArg, "integer");
  }
  const int oneBasedQueueIndex = static_cast<int>(static_cast<std::int64_t>(lua_tonumber(state->m_state, 1)));

  LuaPlus::LuaStackObject countArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&countArg, "integer");
  }
  std::int32_t remaining = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  const CmdId* commandBegin = nullptr;
  const CmdId* commandEnd = nullptr;
  CurrentBuildQueueItemCommands(oneBasedQueueIndex, &commandBegin, &commandEnd);

  // Walk the item's queued command ids from the last-queued command backward.
  for (const CmdId* cursor = commandEnd; cursor != commandBegin; --cursor) {
    const CmdId commandId = *(cursor - 1);

    CommandIssueHelperRuntimeView* const helper = FindCommandIssueHelper(session, commandId);
    if (helper == nullptr) {
      continue;
    }

    const std::int32_t available = QueuedBuildCommandCount(reinterpret_cast<const UserCommandIssueHelper&>(*helper));
    std::int32_t take = remaining;
    if (remaining <= available) {
      remaining = 0;
    } else {
      take = available;
      remaining -= available;
    }

    // The driver marshals the decrement and returns the resulting command cookie;
    // the local event is queued with that cookie (not the input command id).
    ISTIDriver* const activeDriver = SIM_GetActiveDriver();
    const CmdId resultCookie = activeDriver->DecreaseCommandCount(helper->commandId, take);
    QueueCommandIssueDecreaseCountEvent(*helper, resultCookie, take);

    if (remaining <= 0) {
      break;
    }
  }

  return 0;
}

/**
 * Address: 0x00836740 (FUN_00836740, cfunc_IncreaseBuildCountInQueueL)
 *
 * IDA signature:
 * int __usercall cfunc_IncreaseBuildCountInQueueL@<eax>(LuaPlus::LuaState *a1@<eax>);
 *
 * What it does:
 * Lua worker for `IncreaseBuildCountInQueue(queueIndex, count)`. Reads the 1-based
 * factory build-queue item index and a count, then walks that item's queued
 * command ids from the most recently queued command backward. Re-issues the first
 * live factory-build command found (helper present, resolved type == BuildFactory,
 * count > 0) via `ISSUE_IncreaseCommandCount(helper, count)` and stops.
 */
int moho::cfunc_IncreaseBuildCountInQueueL(LuaPlus::LuaState* const state)
{
  // Binary reuses the Decrease help string verbatim here (copy-paste in the
  // original 2007 source: luadef_IncreaseBuildCountInQueue.mHelp -> the Decrease
  // text, proven by the string xref at FUN_008366E0).
  constexpr const char* kIncreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIncreaseBuildCountInQueueHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  LuaPlus::LuaStackObject queueIndexArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&queueIndexArg, "integer");
  }
  const int oneBasedQueueIndex = static_cast<int>(static_cast<std::int64_t>(lua_tonumber(state->m_state, 1)));

  LuaPlus::LuaStackObject countArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&countArg, "integer");
  }
  const int count = static_cast<int>(lua_tonumber(state->m_state, 2));

  const CmdId* commandBegin = nullptr;
  const CmdId* commandEnd = nullptr;
  CurrentBuildQueueItemCommands(oneBasedQueueIndex, &commandBegin, &commandEnd);

  // Walk the item's queued command ids from the last-queued command backward,
  // re-issuing the first live factory-build command found and stopping.
  for (const CmdId* cursor = commandEnd; cursor != commandBegin; --cursor) {
    const CmdId commandId = *(cursor - 1);

    CommandIssueHelperRuntimeView* const helper = FindCommandIssueHelper(session, commandId);
    if (helper == nullptr) {
      continue;
    }

    if (ResolveCommandIssueHelperCommandType(reinterpret_cast<const UserCommandIssueHelper&>(*helper))
          == EUnitCommandType::UNITCOMMAND_BuildFactory
        && count > 0) {
      ISSUE_IncreaseCommandCount(reinterpret_cast<UserCommandIssueHelper*>(helper), count);
      break;
    }
  }

  return 0;
}

/**
 * Address: 0x008440A0 (FUN_008440A0, cfunc_GetSpecialFiles)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilesL`.
 */
int moho::cfunc_GetSpecialFiles(lua_State* const luaContext)
{
  return cfunc_GetSpecialFilesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008440C0 (FUN_008440C0, func_GetSpecialFiles_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFiles`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFiles_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFiles",
    &moho::cfunc_GetSpecialFiles,
    nullptr,
    "<global>",
    kGetSpecialFilesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844120 (FUN_00844120, cfunc_GetSpecialFilesL)
 *
 * What it does:
 * Resolves one special-file type and returns a Lua table containing grouped
 * profile file basenames plus directory/extension metadata.
 */
int moho::cfunc_GetSpecialFilesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFilesHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 1);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 1);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  SpecialFileTypeRuntime specialFileType = SpecialFileTypeRuntime::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  std::string directory{};
  std::string extension{};
  msvc8::map<msvc8::string, msvc8::vector<msvc8::string>> filesByProfile{};
  USER_GetSpecialFiles(specialFileType, directory, extension, filesByProfile);

  LuaPlus::LuaObject filesTable(state);
  filesTable.AssignNewTable(state, 0, 0);

  for (const auto& [profileName, profileFiles] : filesByProfile) {
    LuaPlus::LuaObject profileTable(state);
    profileTable.AssignNewTable(state, 0, 0);

    std::int32_t fileIndex = 1;
    for (const msvc8::string& fileNameWithExtension : profileFiles) {
      const msvc8::string baseFileName = FILE_Base(fileNameWithExtension.c_str(), true);
      profileTable.SetString(fileIndex, baseFileName.c_str());
      ++fileIndex;
    }

    filesTable.SetObject(profileName.c_str(), profileTable);
  }

  LuaPlus::LuaObject result(state);
  result.AssignNewTable(state, 0, 0);
  result.SetObject("files", filesTable);
  result.SetString("directory", directory.c_str());
  result.SetString("extension", extension.c_str());
  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x00844540 (FUN_00844540, cfunc_GetSpecialFilePath)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilePathL`.
 */
int moho::cfunc_GetSpecialFilePath(lua_State* const luaContext)
{
  return cfunc_GetSpecialFilePathL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844560 (FUN_00844560, func_GetSpecialFilePath_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFilePath`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFilePath_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFilePath",
    &moho::cfunc_GetSpecialFilePath,
    nullptr,
    "<global>",
    kGetSpecialFilePathHelpText
  );
  return &binder;
}

/**
 * Address: 0x008445C0 (FUN_008445C0, cfunc_GetSpecialFilePathL)
 *
 * What it does:
 * Resolves `(profile, filename, specialType)` and pushes one absolute
 * user-special-file path (`directory\\profile\\filename.extension`).
 */
int moho::cfunc_GetSpecialFilePathL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFilePathHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject fileNameArg(state, 2);
  const char* const fileName = lua_tostring(rawState, 2);
  if (fileName == nullptr) {
    fileNameArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  SpecialFileTypeRuntime specialFileType = SpecialFileTypeRuntime::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const msvc8::string directory = BuildSpecialFilePathDirectory(specialFileType);
  const msvc8::string extension = BuildSpecialFilePathExtension(specialFileType);
  const msvc8::string fullPath = directory + "\\" + profileName + "\\" + fileName + "." + extension;

  lua_pushstring(rawState, fullPath.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00844C30 (FUN_00844C30, cfunc_GetSpecialFolder)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFolderL`.
 */
int moho::cfunc_GetSpecialFolder(lua_State* const luaContext)
{
  return cfunc_GetSpecialFolderL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844C50 (FUN_00844C50, func_GetSpecialFolder_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFolder`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFolder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFolder",
    &moho::cfunc_GetSpecialFolder,
    nullptr,
    "<global>",
    kGetSpecialFolderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844CB0 (FUN_00844CB0, cfunc_GetSpecialFolderL)
 *
 * What it does:
 * Resolves one special-file type and pushes the matching root folder path.
 */
int moho::cfunc_GetSpecialFolderL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFolderHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 1);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 1);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  SpecialFileTypeRuntime specialFileType = SpecialFileTypeRuntime::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const msvc8::string directory = BuildSpecialFilePathDirectory(specialFileType);
  lua_pushstring(rawState, directory.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00844F10 (FUN_00844F10, cfunc_RemoveSpecialFile)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_RemoveSpecialFileL`.
 */
int moho::cfunc_RemoveSpecialFile(lua_State* const luaContext)
{
  return cfunc_RemoveSpecialFileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844F30 (FUN_00844F30, func_RemoveSpecialFile_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveSpecialFile`.
 */
moho::CScrLuaInitForm* moho::func_RemoveSpecialFile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveSpecialFile",
    &moho::cfunc_RemoveSpecialFile,
    nullptr,
    "<global>",
    kRemoveSpecialFileHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844F90 (FUN_00844F90, cfunc_RemoveSpecialFileL)
 *
 * What it does:
 * Builds one profile-scoped special-file path and recycles it from disk.
 */
int moho::cfunc_RemoveSpecialFileL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveSpecialFileHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  SpecialFileTypeRuntime specialFileType = SpecialFileTypeRuntime::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  msvc8::string directory;
  msvc8::string extension;
  switch (specialFileType) {
    case SpecialFileTypeRuntime::SaveGame:
      directory = USER_GetSaveGameDir();
      extension = USER_GetSaveGameExt();
      break;
    case SpecialFileTypeRuntime::Replay:
      directory = USER_GetReplayDir();
      extension = USER_GetReplayExt();
      break;
    case SpecialFileTypeRuntime::CampaignSave:
      directory = USER_GetSaveGameDir();
      extension = USER_GetCampaignSaveExt();
      break;
    case SpecialFileTypeRuntime::Screenshot:
    default:
      ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject baseNameArg(state, 2);
  const char* const baseName = lua_tostring(rawState, 2);
  if (baseName == nullptr) {
    baseNameArg.TypeError("string");
  }

  const msvc8::string fullPath = directory + profileName + "\\" + baseName + "." + extension;
  DISK_Recycle(fullPath.c_str());
  return 0;
}

/**
 * Address: 0x00845540 (FUN_00845540, cfunc_GetSpecialFileInfo)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFileInfoL`.
 */
int moho::cfunc_GetSpecialFileInfo(lua_State* const luaContext)
{
  return cfunc_GetSpecialFileInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00845560 (FUN_00845560, func_GetSpecialFileInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFileInfo`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFileInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFileInfo",
    &moho::cfunc_GetSpecialFileInfo,
    nullptr,
    "<global>",
    kGetSpecialFileInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008455C0 (FUN_008455C0, cfunc_GetSpecialFileInfoL)
 *
 * What it does:
 * Returns metadata table for one profile-scoped special file, or `nil` when
 * the file does not exist.
 */
int moho::cfunc_GetSpecialFileInfoL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFileInfoHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  SpecialFileTypeRuntime specialFileType = SpecialFileTypeRuntime::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  msvc8::string directory;
  msvc8::string extension;
  switch (specialFileType) {
    case SpecialFileTypeRuntime::SaveGame:
      directory = USER_GetSaveGameDir();
      extension = USER_GetSaveGameExt();
      break;
    case SpecialFileTypeRuntime::Replay:
      directory = USER_GetReplayDir();
      extension = USER_GetReplayExt();
      break;
    case SpecialFileTypeRuntime::CampaignSave:
      directory = USER_GetSaveGameDir();
      extension = USER_GetCampaignSaveExt();
      break;
    case SpecialFileTypeRuntime::Screenshot:
    default:
      ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject baseNameArg(state, 2);
  const char* const baseName = lua_tostring(rawState, 2);
  if (baseName == nullptr) {
    baseNameArg.TypeError("string");
  }

  const msvc8::string fullPath = directory + profileName + "\\" + baseName + "." + extension;
  const std::wstring widePath = gpg::STR_Utf8ToWide(fullPath.c_str());

  WIN32_FILE_ATTRIBUTE_DATA attributeData{};
  if (::GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &attributeData) == FALSE) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject fileInfo(state);
  fileInfo.AssignNewTable(state, 0, 0u);
  fileInfo.SetBoolean("IsFolder", (attributeData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u);
  fileInfo.SetBoolean("ReadOnly", (attributeData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0u);
  fileInfo.SetInteger("SizeBytes", static_cast<std::int32_t>(attributeData.nFileSizeLow));

  ULARGE_INTEGER writeTimeStamp{};
  writeTimeStamp.LowPart = attributeData.ftLastWriteTime.dwLowDateTime;
  writeTimeStamp.HighPart = attributeData.ftLastWriteTime.dwHighDateTime;
  const msvc8::string stampText = gpg::STR_Printf("%016llx", static_cast<unsigned long long>(writeTimeStamp.QuadPart));
  fileInfo.SetString("TimeStamp", stampText.c_str());

  FILETIME localWriteFileTime{};
  SYSTEMTIME localWriteTime{};
  (void)::FileTimeToLocalFileTime(&attributeData.ftLastWriteTime, &localWriteFileTime);
  (void)::FileTimeToSystemTime(&localWriteFileTime, &localWriteTime);

  LuaPlus::LuaObject writeTimeTable(state);
  writeTimeTable.AssignNewTable(state, 0, 0u);
  writeTimeTable.SetInteger("year", static_cast<std::int32_t>(localWriteTime.wYear));
  writeTimeTable.SetInteger("month", static_cast<std::int32_t>(localWriteTime.wMonth));
  writeTimeTable.SetInteger("mday", static_cast<std::int32_t>(localWriteTime.wDay));
  writeTimeTable.SetInteger("wday", static_cast<std::int32_t>(localWriteTime.wDayOfWeek));
  writeTimeTable.SetInteger("hour", static_cast<std::int32_t>(localWriteTime.wHour));
  writeTimeTable.SetInteger("minute", static_cast<std::int32_t>(localWriteTime.wMinute));
  writeTimeTable.SetInteger("second", static_cast<std::int32_t>(localWriteTime.wSecond));
  fileInfo.SetObject("WriteTime", writeTimeTable);

  fileInfo.PushStack(state);
  return 1;
}

/**
 * Address: 0x00845DF0 (FUN_00845DF0, cfunc_RemoveProfileDirectories)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_RemoveProfileDirectoriesL`.
 */
int moho::cfunc_RemoveProfileDirectories(lua_State* const luaContext)
{
  return cfunc_RemoveProfileDirectoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00845E10 (FUN_00845E10, func_RemoveProfileDirectories_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveProfileDirectories`.
 */
moho::CScrLuaInitForm* moho::func_RemoveProfileDirectories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveProfileDirectories",
    &moho::cfunc_RemoveProfileDirectories,
    nullptr,
    "<global>",
    kRemoveProfileDirectoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00845E70 (FUN_00845E70, cfunc_RemoveProfileDirectoriesL)
 *
 * What it does:
 * Recycles replay/save profile-scoped directories and companion lanes for one
 * profile string.
 */
int moho::cfunc_RemoveProfileDirectoriesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveProfileDirectoriesHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(state->m_state, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  // Binary lane calls replay/save directory helpers twice each before recycling.
  const msvc8::string replayProfilePathA = USER_GetReplayDir() + profileName;
  const msvc8::string saveProfilePathA = USER_GetSaveGameDir() + profileName;
  const msvc8::string replayProfilePathB = USER_GetReplayDir() + profileName;
  const msvc8::string saveProfilePathB = USER_GetSaveGameDir() + profileName;

  DISK_Recycle(replayProfilePathA.c_str());
  DISK_Recycle(saveProfilePathA.c_str());
  DISK_Recycle(replayProfilePathB.c_str());
  DISK_Recycle(saveProfilePathB.c_str());
  return 0;
}

/**
 * Address: 0x00846200 (FUN_00846200, cfunc_CopyCurrentReplay)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_CopyCurrentReplayL`.
 */
int moho::cfunc_CopyCurrentReplay(lua_State* const luaContext)
{
  return cfunc_CopyCurrentReplayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846220 (FUN_00846220, func_CopyCurrentReplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CopyCurrentReplay`.
 */
moho::CScrLuaInitForm* moho::func_CopyCurrentReplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CopyCurrentReplay",
    &moho::cfunc_CopyCurrentReplay,
    nullptr,
    "<global>",
    kCopyCurrentReplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00846280 (FUN_00846280, cfunc_CopyCurrentReplayL)
 *
 * What it does:
 * Copies the localized `LastGame` replay from one profile lane to a new replay
 * filename in that profile.
 */
int moho::cfunc_CopyCurrentReplayL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCopyCurrentReplayHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(state->m_state, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject filenameArg(state, 2);
  const char* const newFilename = lua_tostring(state->m_state, 2);
  if (newFilename == nullptr) {
    filenameArg.TypeError("string");
  }

  const msvc8::string replayDirectory = USER_GetReplayDir();
  const msvc8::string replayExtension = USER_GetReplayExt();
  const msvc8::string localizedLastGame = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
  const msvc8::string replayPrefix = replayDirectory + profileName + "\\";

  const msvc8::string sourcePath = replayPrefix + localizedLastGame + "." + replayExtension;
  const msvc8::string destinationPath = replayPrefix + newFilename + "." + replayExtension;

  const std::wstring destinationWide = gpg::STR_Utf8ToWide(destinationPath.c_str());
  const std::wstring sourceWide = gpg::STR_Utf8ToWide(sourcePath.c_str());
  if (::CopyFileW(sourceWide.c_str(), destinationWide.c_str(), FALSE) == FALSE) {
    const msvc8::string lastError = WIN_GetLastError();
    gpg::Logf("Unable to copy replay file: %s", lastError.c_str());
  }
  return 0;
}

/**
 * Address: 0x00846F70 (FUN_00846F70, cfunc_SetOverlayFilters)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetOverlayFiltersL`.
 */
int moho::cfunc_SetOverlayFilters(lua_State* const luaContext)
{
  return cfunc_SetOverlayFiltersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846F90 (FUN_00846F90, func_SetOverlayFilters_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetOverlayFilters`.
 */
moho::CScrLuaInitForm* moho::func_SetOverlayFilters_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetOverlayFilters",
    &moho::cfunc_SetOverlayFilters,
    nullptr,
    "<global>",
    kSetOverlayFiltersHelpText
  );
  return &binder;
}

/**
 * Address: 0x008471C0 (FUN_008471C0, cfunc_GenerateBuildTemplateFromSelection)
 *
 * IDA signature:
 * int __cdecl cfunc_GenerateBuildTemplateFromSelection(LuaPlus::LuaState *a1);
 *
 * What it does:
 * Lua callback for the global `GenerateBuildTemplateFromSelection()` binding.
 * Resolves the LuaPlus state wrapper (result unused) and, when a world session
 * is active, regenerates its build templates from the current selection.
 * Pushes no return values.
 */
int moho::cfunc_GenerateBuildTemplateFromSelection(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    session->GenerateBuildTemplates();
  }

  return 0;
}

/**
 * Address: 0x008471F0 (FUN_008471F0, func_GenerateBuildTemplateFromSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GenerateBuildTemplateFromSelection()` Lua binder metadata.
 */
moho::CScrLuaInitForm* moho::func_GenerateBuildTemplateFromSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GenerateBuildTemplateFromSelection",
    &moho::cfunc_GenerateBuildTemplateFromSelection,
    nullptr,
    "<global>",
    kGenerateBuildTemplateFromSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00846FF0 (FUN_00846FF0, cfunc_SetOverlayFiltersL)
 *
 * What it does:
 * Reads one Lua table of overlay filter strings and replaces
 * `CWldSession::mOverlayFilters`.
 */
int moho::cfunc_SetOverlayFiltersL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetOverlayFiltersHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  LuaPlus::LuaObject filterTable(LuaPlus::LuaStackObject(state, 1));
  if (!filterTable.IsTable()) {
    return 0;
  }

  msvc8::vector<msvc8::string> parsedFilters{};
  for (LuaPlus::LuaTableIterator iter(&filterTable, 1); !iter.m_isDone; iter.Next()) {
    LuaPlus::LuaObject filterValue = iter.GetValue();
    const char* const filterText = filterValue.GetString();
    parsedFilters.push_back(msvc8::string(filterText, std::strlen(filterText)));
  }

  session->mOverlayFilters = std::move(parsedFilters);
  return 0;
}

/**
 * Address: 0x00847A20 (FUN_00847A20, cfunc_ClearBuildTemplates)
 *
 * What it does:
 * Clears user-session build-template state when a world session is active.
 */
int moho::cfunc_ClearBuildTemplates(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);
  if (CWldSession* const session = WLD_GetActiveSession()) {
    session->ClearBuildTemplates();
  }
  return 0;
}

/**
 * Address: 0x00847A50 (FUN_00847A50, func_ClearBuildTemplates_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `ClearBuildTemplates`.
 */
moho::CScrLuaInitForm* moho::func_ClearBuildTemplates_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearBuildTemplates",
    &moho::cfunc_ClearBuildTemplates,
    nullptr,
    "<global>",
    kClearBuildTemplatesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847AD0 (FUN_00847AD0, cfunc_RenderOverlayMilitary)
 *
 * What it does:
 * Retains legacy `RenderOverlayMilitary(bool)` argument validation and emits a
 * deprecation warning.
 */
int moho::cfunc_RenderOverlayMilitary(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRenderOverlayMilitaryHelpText, 1, argumentCount);
  }
  gpg::Warnf("RenderOverlayMilitary is deprecated");
  return 0;
}

/**
 * Address: 0x00847B20 (FUN_00847B20, func_RenderOverlayMilitary_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `RenderOverlayMilitary`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayMilitary_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RenderOverlayMilitary",
    &moho::cfunc_RenderOverlayMilitary,
    nullptr,
    "<global>",
    kRenderOverlayMilitaryHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847BC0 (FUN_00847BC0, cfunc_RenderOverlayIntel)
 *
 * What it does:
 * Retains legacy `RenderOverlayIntel(bool)` argument validation and emits a
 * deprecation warning.
 */
int moho::cfunc_RenderOverlayIntel(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRenderOverlayIntelHelpText, 1, argumentCount);
  }
  gpg::Warnf("RenderOverlayIntel is deprecated");
  return 0;
}

/**
 * Address: 0x00847C10 (FUN_00847C10, func_RenderOverlayIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `RenderOverlayIntel`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RenderOverlayIntel",
    &moho::cfunc_RenderOverlayIntel,
    nullptr,
    "<global>",
    kRenderOverlayIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847CB0 (FUN_00847CB0, cfunc_RenderOverlayEconomy)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_RenderOverlayEconomyL`.
 */
int moho::cfunc_RenderOverlayEconomy(lua_State* const luaContext)
{
  return cfunc_RenderOverlayEconomyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847CD0 (FUN_00847CD0, func_RenderOverlayEconomy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for
 * `RenderOverlayEconomy`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayEconomy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RenderOverlayEconomy",
    &moho::cfunc_RenderOverlayEconomy,
    nullptr,
    "<global>",
    kRenderOverlayEconomyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847D30 (FUN_00847D30, cfunc_RenderOverlayEconomyL)
 *
 * What it does:
 * Reads one Lua bool and updates the active user session economy-overlay flag.
 */
int moho::cfunc_RenderOverlayEconomyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRenderOverlayEconomyHelpText, 1, argumentCount);
  }

  if (CWldSession* const session = WLD_GetActiveSession()) {
    const LuaPlus::LuaStackObject enabledArg(state, 1);
    session->DisplayEconomyOverlay = enabledArg.GetBoolean();
  }
  return 0;
}

/**
 * Address: 0x00847D90 (FUN_00847D90, cfunc_TeamColorMode)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_TeamColorModeL`.
 */
int moho::cfunc_TeamColorMode(lua_State* const luaContext)
{
  return cfunc_TeamColorModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847DB0 (FUN_00847DB0, func_TeamColorMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `TeamColorMode`.
 */
moho::CScrLuaInitForm* moho::func_TeamColorMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "TeamColorMode",
    &moho::cfunc_TeamColorMode,
    nullptr,
    "<global>",
    kTeamColorModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847E10 (FUN_00847E10, cfunc_TeamColorModeL)
 *
 * What it does:
 * Validates one Lua bool and updates the active user session team-color mode.
 */
int moho::cfunc_TeamColorModeL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kTeamColorModeHelpText, 1, argumentCount);
  }

  if (CWldSession* const session = WLD_GetActiveSession()) {
    const LuaPlus::LuaStackObject modeArg(state, 1);
    if (lua_type(state->m_state, 1) != LUA_TBOOLEAN) {
      modeArg.TypeError("bool");
    }
    session->mTeamColorMode = modeArg.GetBoolean();
  }
  return 0;
}

/**
 * Address: 0x00847E70 (FUN_00847E70, cfunc_GetUnitByIdUser)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitByIdUserL`.
 */
int moho::cfunc_GetUnitByIdUser(lua_State* const luaContext)
{
  return cfunc_GetUnitByIdUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847E90 (FUN_00847E90, func_GetUnitByIdUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `GetUnitById`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitByIdUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetUnitById",
    &moho::cfunc_GetUnitByIdUser,
    nullptr,
    "<global>",
    kGetUnitByIdUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847EF0 (FUN_00847EF0, cfunc_GetUnitByIdUserL)
 *
 * What it does:
 * Resolves one entity id through user-session map lanes and returns the
 * matching user-unit Lua object, or `nil` when no unit is found.
 */
int moho::cfunc_GetUnitByIdUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitByIdUserHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const std::int32_t entityId = std::atoi(entityIdText);
  UserEntity* const entity = FindUserSessionEntityById(session, entityId);
  UserUnit* const userUnit = entity ? entity->IsUserUnit() : nullptr;
  if (userUnit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  GetUserUnitLuaObjectView(userUnit).luaObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0128B0BF (FUN_0128B0BF, cfunc_GetTimeForProfileSim)
 *
 * What it does:
 * Reads start time from Lua arg #1 and pushes elapsed time in seconds from
 * `QueryPerformanceCounter`.
 */
int moho::cfunc_GetTimeForProfileSim(lua_State* const luaContext)
{
  LARGE_INTEGER performanceCount{};
  LARGE_INTEGER frequency{};
  ::QueryPerformanceCounter(&performanceCount);
  ::QueryPerformanceFrequency(&frequency);

  const float startSeconds = static_cast<float>(lua_tonumber(luaContext, 1));
  const float frequencyValue = static_cast<float>(frequency.QuadPart);
  const float counterValue = static_cast<float>(performanceCount.QuadPart);
  const float elapsedSeconds = (counterValue - (startSeconds * frequencyValue)) / frequencyValue;
  lua_pushnumber(luaContext, elapsedSeconds);
  return 1;
}

/**
 * Address: 0x0128B2F9 (FUN_0128B2F9, cfunc_SetInvertMidMouseButton)
 *
 * What it does:
 * Reads one Lua boolean, patches middle-mouse scrub opcodes to add/sub mode,
 * and preserves page protection around the patch write.
 */
int moho::cfunc_SetInvertMidMouseButton(lua_State* const luaContext)
{
  const int argumentCount = lua_gettop(luaContext);
  if (argumentCount != 1) {
    gpg::Warnf(kLuaExpectedArgsWarning, kSetInvertMidMouseButtonHelpText, 1, argumentCount);
  }

  if (lua_type(luaContext, 1) != LUA_TBOOLEAN) {
    gpg::Warnf(kLuaInvalidBoolWarning, kSetInvertMidMouseButtonHelpText, 1);
  }

  const bool invertMiddleMouse = lua_toboolean(luaContext, 1) != 0;
  UI_SetInvertMidMouseScrub(invertMiddleMouse);
  return 0;
}

/**
 * What it does:
 * Publishes the global Lua binder definition for `SetInvertMidMouseButton`.
 *
 * The shipped build carries this binding in its `.exxt` patch section rather
 * than a `func_*_LuaFuncDef` factory, so there is no address to cite for the
 * factory itself - only for the bound worker, `cfunc_SetInvertMidMouseButton`
 * at 0x0128B2F9. `/lua/options/options.lua` calls the global from the
 * `invert_middle_mouse_button` option's `set` handler, which runs at startup,
 * so without this registration every options pass died on "access to
 * nonexistent global variable".
 */
moho::CScrLuaInitForm* moho::func_SetInvertMidMouseButton_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetInvertMidMouseButton",
    &moho::cfunc_SetInvertMidMouseButton,
    nullptr,
    "<global>",
    kSetInvertMidMouseButtonHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074B570 (FUN_0074B570, cfunc_printSim)
 *
 * What it does:
 * Concatenates Lua print arguments and emits one line into sim print/log
 * output.
 */
int moho::cfunc_printSim(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  if (!state || !state->m_state) {
    return 0;
  }

  SCR_ConcatArgsAndCall(state, '\t', &PrintSimConcatSink);
  return 0;
}

/**
 * Address: 0x0074B590 (FUN_0074B590, func_printSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `print(...)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_printSim_LuaFuncDef()
{
  static CScrLuaBinder binder(SimLuaInitSet(), "print", &moho::cfunc_printSim, nullptr, "<global>", kPrintSimHelpText);
  return &binder;
}

/**
 * Address: 0x0074B620 (FUN_0074B620, cfunc_CheatsEnabled)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_CheatsEnabledL`.
 */
int moho::cfunc_CheatsEnabled(lua_State* const luaContext)
{
  return cfunc_CheatsEnabledL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074B640 (FUN_0074B640, func_CheatsEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes global `CheatsEnabled()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_CheatsEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CheatsEnabled",
    &moho::cfunc_CheatsEnabled,
    nullptr,
    "<global>",
    kCheatsEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074B6A0 (FUN_0074B6A0, cfunc_CheatsEnabledL)
 *
 * What it does:
 * Validates no Lua args and returns `Sim::CheatsEnabled()` as a boolean.
 */
int moho::cfunc_CheatsEnabledL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCheatsEnabledHelpText, 0, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(state->m_state);
  const bool cheatsEnabled = sim != nullptr && sim->CheatsEnabled();
  lua_pushboolean(state->m_state, cheatsEnabled ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0074B710 (FUN_0074B710, cfunc_GetCurrentCommandSource)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_GetCurrentCommandSourceL`.
 */
int moho::cfunc_GetCurrentCommandSource(lua_State* const luaContext)
{
  return cfunc_GetCurrentCommandSourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074B730 (FUN_0074B730, func_GetCurrentCommandSource_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetCurrentCommandSource()` Lua binder in the sim init
 * set.
 */
moho::CScrLuaInitForm* moho::func_GetCurrentCommandSource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetCurrentCommandSource",
    &moho::cfunc_GetCurrentCommandSource,
    nullptr,
    "<global>",
    kGetCurrentCommandSourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074B790 (FUN_0074B790, cfunc_GetCurrentCommandSourceL)
 *
 * What it does:
 * Returns the current command source index as 1-based Lua number, or nil
 * when no source is active.
 */
int moho::cfunc_GetCurrentCommandSourceL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCurrentCommandSourceHelpText, 0, argumentCount);
  }

  const Sim* const sim = ResolveGlobalSim(state->m_state);
  const SSTICommandSource* const source = sim != nullptr ? sim->GetCurrentCommandSource() : nullptr;
  if (source == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  lua_pushnumber(state->m_state, static_cast<float>(source->mIndex + 1u));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0128C8F0 (FUN_0128C8F0, cfunc_EndGameL)
 *
 * What it does:
 * Validates Lua argument count and forwards to `Sim::EndGame()`.
 */
int moho::cfunc_EndGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    luaL_error(rawState, "%s\n  expected %d args, but got %d", kEndGameHelpText, 0, argumentCount);
  }

  if (Sim* const sim = ResolveGlobalSim(rawState)) {
    sim->EndGame();
  }

  return 0;
}

/**
 * Address: 0x0074B830 (FUN_0074B830, cfunc_EndGame)
 * Address: 0x0128F085 (FUN_0128F085 thunk)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_EndGameL`.
 */
int moho::cfunc_EndGame(lua_State* const luaContext)
{
  return cfunc_EndGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074B980 (FUN_0074B980, cfunc_IsGameOverL)
 *
 * What it does:
 * Validates Lua argument count and pushes Sim end-game state.
 */
int moho::cfunc_IsGameOverL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    luaL_error(rawState, "%s\n  expected %d args, but got %d", kIsGameOverHelpText, 0, argumentCount);
  }

  const Sim* const sim = ResolveGlobalSim(rawState);
  const bool isGameOver = sim && (sim->mGameEnded || sim->mGameOver);
  lua_pushboolean(rawState, isGameOver ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0074B900 (FUN_0074B900, cfunc_IsGameOver)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_IsGameOverL`.
 */
int moho::cfunc_IsGameOver(lua_State* const luaContext)
{
  return cfunc_IsGameOverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A5A0 (FUN_0075A5A0, func_GenerateRandomOrientation_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GenerateRandomOrientation()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GenerateRandomOrientation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GenerateRandomOrientation",
    &moho::cfunc_GenerateRandomOrientation,
    nullptr,
    "<global>",
    kGenerateRandomOrientationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A580 (FUN_0075A580, cfunc_GenerateRandomOrientation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GenerateRandomOrientationL`.
 */
int moho::cfunc_GenerateRandomOrientation(lua_State* const luaContext)
{
  return cfunc_GenerateRandomOrientationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A600 (FUN_0075A600, cfunc_GenerateRandomOrientationL)
 *
 * What it does:
 * Samples four Gaussian random lanes, normalizes one quaternion, and returns
 * it as a Lua quaternion object.
 */
int moho::cfunc_GenerateRandomOrientationL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGenerateRandomOrientationHelpText, 0, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  CRandomStream* const random = sim->mRngState;

  Wm3::Quaternionf orientation{};
  orientation.y = random->FRandGaussian();
  orientation.z = random->FRandGaussian();
  orientation.w = random->FRandGaussian();
  orientation.x = random->FRandGaussian();

  const float magnitude = std::sqrt(
    (orientation.x * orientation.x) + (orientation.y * orientation.y) + (orientation.z * orientation.z) +
    (orientation.w * orientation.w)
  );
  if (magnitude <= 1.0e-6f) {
    orientation = Wm3::Quaternionf{};
  } else {
    const float inverseMagnitude = 1.0f / magnitude;
    orientation.x *= inverseMagnitude;
    orientation.y *= inverseMagnitude;
    orientation.z *= inverseMagnitude;
    orientation.w *= inverseMagnitude;
  }

  LuaPlus::LuaObject rotationObject = SCR_ToLua<Wm3::Quaternionf>(state, orientation);
  rotationObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075A770 (FUN_0075A770, cfunc_GetGameTimeSecondsSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetGameTimeSecondsSimL`.
 */
int moho::cfunc_GetGameTimeSecondsSim(lua_State* const luaContext)
{
  return cfunc_GetGameTimeSecondsSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A790 (FUN_0075A790, func_GetGameTimeSecondsSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetGameTimeSeconds()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_GetGameTimeSecondsSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetGameTimeSeconds",
    &moho::cfunc_GetGameTimeSecondsSim,
    nullptr,
    "<global>",
    kGetGameTimeSecondsSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A7F0 (FUN_0075A7F0, cfunc_GetGameTimeSecondsSimL)
 *
 * What it does:
 * Validates no Lua args and returns simulation time in seconds.
 */
int moho::cfunc_GetGameTimeSecondsSimL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameTimeSecondsSimHelpText, 0, argumentCount);
  }

  const Sim* const sim = ResolveGlobalSim(state->m_state);
  lua_pushnumber(state->m_state, static_cast<float>(sim->mCurTick) * 0.1f);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075A860 (FUN_0075A860, cfunc_GetGameTick)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetGameTickL`.
 */
int moho::cfunc_GetGameTick(lua_State* const luaContext)
{
  return cfunc_GetGameTickL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A880 (FUN_0075A880, func_GetGameTick_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetGameTick()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_GetGameTick_LuaFuncDef()
{
  static CScrLuaBinder
    binder(SimLuaInitSet(), "GetGameTick", &moho::cfunc_GetGameTick, nullptr, "<global>", kGetGameTickHelpText);
  return &binder;
}

/**
 * Address: 0x0075A8E0 (FUN_0075A8E0, cfunc_GetGameTickL)
 *
 * What it does:
 * Validates no Lua args and returns simulation tick count.
 */
int moho::cfunc_GetGameTickL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameTickHelpText, 0, argumentCount);
  }

  const Sim* const sim = ResolveGlobalSim(state->m_state);
  lua_pushnumber(state->m_state, static_cast<float>(sim->mCurTick));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075A950 (FUN_0075A950, cfunc_GetSystemTimeSecondsOnlyForProfileUse)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_GetSystemTimeSecondsOnlyForProfileUseL`.
 */
int moho::cfunc_GetSystemTimeSecondsOnlyForProfileUse(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeSecondsOnlyForProfileUseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A970 (FUN_0075A970, func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetSystemTimeSecondsOnlyForProfileUse()` Lua binder in
 * the sim init set.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetSystemTimeSecondsOnlyForProfileUse",
    &moho::cfunc_GetSystemTimeSecondsOnlyForProfileUse,
    nullptr,
    "<global>",
    kGetSystemTimeSecondsOnlyForProfileUseHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A9D0 (FUN_0075A9D0, cfunc_GetSystemTimeSecondsOnlyForProfileUseL)
 *
 * What it does:
 * Validates no Lua args and returns system timer elapsed seconds.
 */
int moho::cfunc_GetSystemTimeSecondsOnlyForProfileUseL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kGetSystemTimeSecondsOnlyForProfileUseHelpText,
      0,
      argumentCount
    );
  }

  lua_pushnumber(state->m_state, gpg::time::GetSystemTimer().ElapsedSeconds());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075AA30 (FUN_0075AA30, cfunc_GetEntitiesInRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetEntitiesInRectL`.
 */
int moho::cfunc_GetEntitiesInRect(lua_State* const luaContext)
{
  return cfunc_GetEntitiesInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075AA50 (FUN_0075AA50, func_GetEntitiesInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetEntitiesInRect(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetEntitiesInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetEntitiesInRect",
    &moho::cfunc_GetEntitiesInRect,
    nullptr,
    "<global>",
    kGetEntitiesInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075AAB0 (FUN_0075AAB0, cfunc_GetEntitiesInRectL)
 *
 * What it does:
 * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
 * entities (unit/prop/projectile/entity) inside the query rectangle.
 */
int moho::cfunc_GetEntitiesInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kGetEntitiesInRectHelpText,
      1,
      4,
      argumentCount
    );
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;
  if (oGrid == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::Rect2f queryRect{};
  if (lua_gettop(rawState) == 1) {
    auto rectObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
    queryRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
  } else {
    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
    }
    queryRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z0Arg, "number");
    }
    queryRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
    }
    queryRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z1Arg, "number");
    }
    queryRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
  }

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  CollisionSpanVector gatheredSpans{};
  constexpr EEntityType kEntityMask = static_cast<EEntityType>(
    ENTITYTYPE_Unit | ENTITYTYPE_Prop | ENTITYTYPE_Projectile | ENTITYTYPE_Entity
  );
  const int gatheredCount = oGrid->mEntityOccupationManager.GatherUnmarkedUnitsInRect(
    gatheredSpans,
    collisionRect,
    kEntityMask
  );
  if (gatheredCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  auto resultTable = LuaPlus::LuaObject();
  resultTable.AssignNewTable(state, gatheredCount, 0);
  int luaIndex = 1;
  for (int index = 0; index < gatheredCount; ++index) {
    auto* const rawSpan = reinterpret_cast<std::uint8_t*>(gatheredSpans[index]) - 0x4Cu;
    Entity* const entity = reinterpret_cast<Entity*>(rawSpan);
    const auto entityObject = LuaPlus::LuaObject(entity->mLuaObj);
    resultTable.SetObject(luaIndex, entityObject);
    ++luaIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075AE00 (FUN_0075AE00, cfunc_GetUnitsInRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitsInRectL`.
 */
int moho::cfunc_GetUnitsInRect(lua_State* const luaContext)
{
  return cfunc_GetUnitsInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075AE20 (FUN_0075AE20, func_GetUnitsInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetUnitsInRect(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetUnitsInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetUnitsInRect",
    &moho::cfunc_GetUnitsInRect,
    nullptr,
    "<global>",
    kGetUnitsInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075AE80 (FUN_0075AE80, cfunc_GetUnitsInRectL)
 *
 * What it does:
 * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
 * unit objects inside the query rectangle.
 */
int moho::cfunc_GetUnitsInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kGetUnitsInRectHelpText,
      1,
      4,
      argumentCount
    );
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;
  if (oGrid == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::Rect2f queryRect{};
  if (lua_gettop(rawState) == 1) {
    auto rectObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
    queryRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
  } else {
    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
    }
    queryRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z0Arg, "number");
    }
    queryRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
    }
    queryRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z1Arg, "number");
    }
    queryRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
  }

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  CollisionSpanVector gatheredSpans{};
  const int gatheredCount =
    oGrid->mEntityOccupationManager.GatherUnmarkedUnitsInRect(gatheredSpans, collisionRect, ENTITYTYPE_Unit);
  if (gatheredCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  auto resultTable = LuaPlus::LuaObject();
  resultTable.AssignNewTable(state, gatheredCount, 0);
  int luaIndex = 1;
  for (int index = 0; index < gatheredCount; ++index) {
    auto* const rawSpan = reinterpret_cast<std::uint8_t*>(gatheredSpans[index]) - 0x4Cu;
    Entity* const entity = reinterpret_cast<Entity*>(rawSpan);
    Unit* const unit = entity != nullptr ? entity->IsUnit() : nullptr;
    if (unit == nullptr) {
      continue;
    }

    const auto unitObject = LuaPlus::LuaObject(unit->GetLuaObject());
    resultTable.SetObject(luaIndex, unitObject);
    ++luaIndex;
  }

  if (luaIndex <= 1) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075B200 (FUN_0075B200, cfunc_GetReclaimablesInRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_GetReclaimablesInRectL`.
 */
int moho::cfunc_GetReclaimablesInRect(lua_State* const luaContext)
{
  return cfunc_GetReclaimablesInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075B220 (FUN_0075B220, func_GetReclaimablesInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetReclaimablesInRect(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetReclaimablesInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetReclaimablesInRect",
    &moho::cfunc_GetReclaimablesInRect,
    nullptr,
    "<global>",
    kGetReclaimablesInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075B280 (FUN_0075B280, cfunc_GetReclaimablesInRectL)
 *
 * What it does:
 * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
 * reclaimable entity objects (units/props) inside the query rectangle.
 */
int moho::cfunc_GetReclaimablesInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kGetReclaimablesInRectHelpText,
      1,
      4,
      argumentCount
    );
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;
  if (oGrid == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::Rect2f queryRect{};
  if (lua_gettop(rawState) == 1) {
    auto rectObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
    queryRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
  } else {
    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
    }
    queryRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z0Arg, "number");
    }
    queryRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
    }
    queryRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z1Arg, "number");
    }
    queryRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
  }

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  CollisionSpanVector gatheredSpans{};
  constexpr EEntityType kReclaimableMask = static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Prop);
  const int gatheredCount = oGrid->mEntityOccupationManager.GatherUnmarkedUnitsInRect(
    gatheredSpans,
    collisionRect,
    kReclaimableMask
  );
  if (gatheredCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  auto resultTable = LuaPlus::LuaObject();
  resultTable.AssignNewTable(state, gatheredCount, 0);
  int luaIndex = 1;
  for (int index = 0; index < gatheredCount; ++index) {
    auto* const rawSpan = reinterpret_cast<std::uint8_t*>(gatheredSpans[index]) - 0x4Cu;
    Entity* const entity = reinterpret_cast<Entity*>(rawSpan);
    const auto entityObject = LuaPlus::LuaObject(entity->mLuaObj);
    resultTable.SetObject(luaIndex, entityObject);
    ++luaIndex;
  }

  if (luaIndex <= 1) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075BBE0 (FUN_0075BBE0, cfunc_GetMapSize)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetMapSizeL`.
 */
int moho::cfunc_GetMapSize(lua_State* const luaContext)
{
  return cfunc_GetMapSizeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075BC00 (FUN_0075BC00, func_GetMapSize_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetMapSize()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetMapSize_LuaFuncDef()
{
  static CScrLuaBinder
    binder(SimLuaInitSet(), "GetMapSize", &moho::cfunc_GetMapSize, nullptr, "<global>", kGetMapSizeHelpText);
  return &binder;
}

/**
 * Address: 0x0075BC60 (FUN_0075BC60, cfunc_GetMapSizeL)
 *
 * What it does:
 * Validates no Lua args and returns map width/height extents in terrain grid
 * coordinates.
 */
int moho::cfunc_GetMapSizeL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetMapSizeHelpText, 0, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(state->m_state);
  STIMap* const map = sim->mMapData;
  CHeightField* const field = map->mHeightField.get();
  lua_pushnumber(state->m_state, static_cast<float>(field->width - 1));
  (void)lua_gettop(state->m_state);
  lua_pushnumber(state->m_state, static_cast<float>(field->height - 1));
  (void)lua_gettop(state->m_state);
  return 2;
}

/**
 * Address: 0x0075BD10 (FUN_0075BD10, func_GetTerrainHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetTerrainHeight(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetTerrainHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTerrainHeight",
    &moho::cfunc_GetTerrainHeight,
    nullptr,
    "<global>",
    kGetTerrainHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075BCF0 (FUN_0075BCF0, cfunc_GetTerrainHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetTerrainHeightL`.
 */
int moho::cfunc_GetTerrainHeight(lua_State* const luaContext)
{
  return cfunc_GetTerrainHeightL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075BD70 (FUN_0075BD70, cfunc_GetTerrainHeightL)
 *
 * What it does:
 * Reads `(x, z)` and returns terrain elevation sampled from map heightfield.
 */
int moho::cfunc_GetTerrainHeightL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetTerrainHeightHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 2));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  CHeightField* const field = map ? map->mHeightField.get() : nullptr;
  const float terrainHeight = field ? field->GetElevation(x, z) : 0.0f;
  lua_pushnumber(rawState, terrainHeight);
  return 1;
}

/**
 * Address: 0x0075BE90 (FUN_0075BE90, func_GetSurfaceHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetSurfaceHeight(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetSurfaceHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetSurfaceHeight",
    &moho::cfunc_GetSurfaceHeight,
    nullptr,
    "<global>",
    kGetSurfaceHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075BE70 (FUN_0075BE70, cfunc_GetSurfaceHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetSurfaceHeightL`.
 */
int moho::cfunc_GetSurfaceHeight(lua_State* const luaContext)
{
  return cfunc_GetSurfaceHeightL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075BEF0 (FUN_0075BEF0, cfunc_GetSurfaceHeightL)
 *
 * What it does:
 * Reads `(x, z)` and returns max(terrainHeight, waterElevation) when water is
 * enabled, otherwise terrain height.
 */
int moho::cfunc_GetSurfaceHeightL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSurfaceHeightHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 2));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  CHeightField* const field = map ? map->mHeightField.get() : nullptr;

  float surfaceHeight = field ? field->GetElevation(x, z) : 0.0f;
  if (map && map->mWaterEnabled != 0u && map->mWaterElevation > surfaceHeight) {
    surfaceHeight = map->mWaterElevation;
  }

  lua_pushnumber(rawState, surfaceHeight);
  return 1;
}

/**
 * Address: 0x0075C050 (FUN_0075C050, func_GetTerrainTypeOffset_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetTerrainTypeOffset(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetTerrainTypeOffset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTerrainTypeOffset",
    &moho::cfunc_GetTerrainTypeOffset,
    nullptr,
    "<global>",
    kGetTerrainTypeOffsetHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C030 (FUN_0075C030, cfunc_GetTerrainTypeOffset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetTerrainTypeOffsetL`.
 */
int moho::cfunc_GetTerrainTypeOffset(lua_State* const luaContext)
{
  return cfunc_GetTerrainTypeOffsetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C0B0 (FUN_0075C0B0, cfunc_GetTerrainTypeOffsetL)
 *
 * What it does:
 * Reads `(x, z)` and returns terrain texture offset value at map position.
 */
int moho::cfunc_GetTerrainTypeOffsetL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetTerrainTypeOffsetHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 2));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  const float terrainTypeOffset = map ? map->GetTerrainTypeOffset(x, z) : 0.0f;
  lua_pushnumber(rawState, terrainTypeOffset);
  return 1;
}

/**
 * Address: 0x0075C1D0 (FUN_0075C1D0, func_GetTerrainType_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetTerrainType(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetTerrainType_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTerrainType",
    &moho::cfunc_GetTerrainType,
    nullptr,
    "<global>",
    kGetTerrainTypeLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C1B0 (FUN_0075C1B0, cfunc_GetTerrainType)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetTerrainTypeL`.
 */
int moho::cfunc_GetTerrainType(lua_State* const luaContext)
{
  return cfunc_GetTerrainTypeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C230 (FUN_0075C230, cfunc_GetTerrainTypeL)
 *
 * What it does:
 * Reads `(x, z)` from Lua, queries terrain type from `Sim::mMapData`, and
 * returns the terrain-type Lua table.
 */
int moho::cfunc_GetTerrainTypeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetTerrainTypeHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject xArg{};
  xArg.m_state = state;
  xArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "integer");
  }
  const std::uint32_t x = static_cast<std::uint32_t>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg{};
  zArg.m_state = state;
  zArg.m_stackIndex = 2;
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "integer");
  }
  const std::uint32_t z = static_cast<std::uint32_t>(lua_tonumber(rawState, 2));

  Sim* const sim = lua_getglobaluserdata(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  LuaPlus::LuaObject terrainType = map->GetTerrainType(x, z);
  terrainType.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075C3D0 (FUN_0075C3D0, func_SetTerrainType_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SetTerrainType(x,z,type)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetTerrainType_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetTerrainType",
    &moho::cfunc_SetTerrainType,
    nullptr,
    "<global>",
    kSetTerrainTypeLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C3B0 (FUN_0075C3B0, cfunc_SetTerrainType)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetTerrainTypeL`.
 */
int moho::cfunc_SetTerrainType(lua_State* const luaContext)
{
  return cfunc_SetTerrainTypeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C430 (FUN_0075C430, cfunc_SetTerrainTypeL)
 *
 * What it does:
 * Reads `(x, z, terrainTypeTable)` from Lua and applies the table `TypeCode`
 * entry through `STIMap::SetTerrainType`.
 */
int moho::cfunc_SetTerrainTypeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetTerrainTypeHelpText, 3, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  LuaPlus::LuaStackObject xArg{};
  xArg.m_state = state;
  xArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "integer");
  }
  const std::uint32_t x = static_cast<std::uint32_t>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg{};
  zArg.m_state = state;
  zArg.m_stackIndex = 2;
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "integer");
  }
  const std::uint32_t z = static_cast<std::uint32_t>(lua_tonumber(rawState, 2));

  lua_pushstring(rawState, "TypeCode");
  lua_gettable(rawState, 3);

  const int typeCodeIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject typeCodeArg{};
  typeCodeArg.m_state = state;
  typeCodeArg.m_stackIndex = typeCodeIndex;
  if (lua_type(rawState, typeCodeIndex) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&typeCodeArg, "integer");
  }
  const std::uint8_t terrainType = static_cast<std::uint8_t>(lua_tonumber(rawState, typeCodeIndex));

  map->SetTerrainType(x, z, terrainType);
  return 0;
}

/**
 * Address: 0x0075F2D0 (FUN_0075F2D0, func_SetTerrainTypeRect)
 *
 * What it does:
 * Writes one terrain-type rectangle into `grid` after clamping
 * `(x, z, x + width, z + height)` against map bounds, preserving the original
 * nested row/column fill order.
 */
static std::int32_t FillTerrainTypeRectClamped(
  const std::int32_t x,
  const std::int32_t z,
  const std::uint8_t terrainType,
  moho::TerrainTypeGrid* const grid,
  const std::int32_t width,
  const std::int32_t height
) noexcept
{
  std::int32_t endX = x + width;
  std::int32_t endZ = z + height;

  std::int32_t startX = x;
  if (startX < 0) {
    startX = 0;
  }

  std::int32_t startZ = z;
  if (startZ < 0) {
    startZ = 0;
  }

  if (endX >= grid->width) {
    endX = grid->width;
  }
  if (endZ >= grid->height) {
    endZ = grid->height;
  }

  std::int32_t result = startX;
  if (endX > startX && startZ < endZ) {
    do {
      if (result < endX) {
        do {
          ++result;
          grid->data[static_cast<std::size_t>(startZ) * static_cast<std::size_t>(grid->width) + static_cast<std::size_t>(result - 1)] =
            terrainType;
        } while (result < endX);
        result = startX;
      }
      ++startZ;
    } while (startZ < endZ);
  }

  return result;
}

/**
 * Address: 0x0075C5F0 (FUN_0075C5F0, func_SetTerrainTypeRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SetTerrainTypeRect(rect,type)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetTerrainTypeRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetTerrainTypeRect",
    &moho::cfunc_SetTerrainTypeRect,
    nullptr,
    "<global>",
    kSetTerrainTypeRectLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C5D0 (FUN_0075C5D0, cfunc_SetTerrainTypeRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetTerrainTypeRectL`.
 */
int moho::cfunc_SetTerrainTypeRect(lua_State* const luaContext)
{
  return cfunc_SetTerrainTypeRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C650 (FUN_0075C650, cfunc_SetTerrainTypeRectL)
 *
 * What it does:
 * Reads `(rectTable, terrainTypeTable)` from Lua and writes one clamped
 * terrain-type rectangle into `STIMap::mTerrainType`.
 */
int moho::cfunc_SetTerrainTypeRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetTerrainTypeRectHelpText, 2, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
  gpg::Rect2i rect{};
  rect.x0 = static_cast<std::int32_t>(rectObject.GetByName("x0").GetNumber());
  rect.z0 = static_cast<std::int32_t>(rectObject.GetByName("y0").GetNumber());
  rect.x1 = static_cast<std::int32_t>(rectObject.GetByName("x1").GetNumber());
  rect.z1 = static_cast<std::int32_t>(rectObject.GetByName("y1").GetNumber());

  lua_pushstring(rawState, "TypeCode");
  lua_gettable(rawState, 2);

  const int typeCodeIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject typeCodeArg{};
  typeCodeArg.m_state = state;
  typeCodeArg.m_stackIndex = typeCodeIndex;
  if (lua_type(rawState, typeCodeIndex) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&typeCodeArg, "integer");
  }
  const std::uint8_t terrainType = static_cast<std::uint8_t>(static_cast<std::int32_t>(lua_tonumber(rawState, typeCodeIndex)));

  TerrainTypeGrid* const terrainTypeGrid = &map->mTerrainType;
  (void)FillTerrainTypeRectClamped(
    rect.x0,
    rect.z0,
    terrainType,
    terrainTypeGrid,
    rect.x1 - rect.x0,
    rect.z1 - rect.z0
  );

  return 0;
}

/**
 * Address: 0x0075C830 (FUN_0075C830, cfunc_SetPlayableRectL)
 *
 * What it does:
 * Reads `(minX, minZ, maxX, maxZ)` from Lua, validates integer lanes,
 * and writes the playable map rectangle through `STIMap::SetPlayableMapRect`.
 */
int moho::cfunc_SetPlayableRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetPlayableRectHelpText, 4, argumentCount);
  }

  LuaPlus::LuaStackObject maxZArg{};
  maxZArg.m_state = state;
  maxZArg.m_stackIndex = 4;
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxZArg, "integer");
  }
  const std::int32_t maxZ = static_cast<std::int32_t>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject maxXArg{};
  maxXArg.m_state = state;
  maxXArg.m_stackIndex = 3;
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxXArg, "integer");
  }
  const std::int32_t maxX = static_cast<std::int32_t>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject minZArg{};
  minZArg.m_state = state;
  minZArg.m_stackIndex = 2;
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&minZArg, "integer");
  }
  const std::int32_t minZ = static_cast<std::int32_t>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject minXArg{};
  minXArg.m_state = state;
  minXArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&minXArg, "integer");
  }
  const std::int32_t minX = static_cast<std::int32_t>(lua_tonumber(rawState, 1));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  gpg::Rect2i playableRect{};
  playableRect.x0 = minX;
  playableRect.z0 = minZ;
  playableRect.x1 = maxX;
  playableRect.z1 = maxZ;
  if (!map->SetPlayableMapRect(playableRect)) {
    LuaPlus::LuaState::Error(state, "Attempted to set an invalid playable rect.");
  }

  return 0;
}

/**
 * Address: 0x0075C7B0 (FUN_0075C7B0, cfunc_SetPlayableRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetPlayableRectL`.
 */
int moho::cfunc_SetPlayableRect(lua_State* const luaContext)
{
  return cfunc_SetPlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C9D0 (FUN_0075C9D0, cfunc_FlushIntelInRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_FlushIntelInRectL`.
 */
int moho::cfunc_FlushIntelInRect(lua_State* const luaContext)
{
  return cfunc_FlushIntelInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C9F0 (FUN_0075C9F0, func_FlushIntelInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `FlushIntelInRect(minX,minZ,maxX,maxZ)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_FlushIntelInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "FlushIntelInRect",
    &moho::cfunc_FlushIntelInRect,
    nullptr,
    "<global>",
    kFlushIntelInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CA50 (FUN_0075CA50, cfunc_FlushIntelInRectL)
 *
 * What it does:
 * Flushes recon blips inside one rectangle for every active army recon db.
 */
int moho::cfunc_FlushIntelInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kFlushIntelInRectHelpText, 4, argumentCount);
  }

  LuaPlus::LuaStackObject maxZArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    maxZArg.TypeError("integer");
  }
  const std::int32_t maxZ = static_cast<std::int32_t>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject maxXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    maxXArg.TypeError("integer");
  }
  const std::int32_t maxX = static_cast<std::int32_t>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject minZArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    minZArg.TypeError("integer");
  }
  const std::int32_t minZ = static_cast<std::int32_t>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject minXArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    minXArg.TypeError("integer");
  }
  const std::int32_t minX = static_cast<std::int32_t>(lua_tonumber(rawState, 1));

  Sim* const sim = ResolveGlobalSim(rawState);
  if (!sim) {
    return 0;
  }

  gpg::Rect2i rect{};
  rect.x0 = minX;
  rect.z0 = minZ;
  rect.x1 = maxX;
  rect.z1 = maxZ;

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (!army) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb) {
      reconDb->ReconFlushBlipsInRect(rect);
    }
  }

  return 0;
}

/**
 * Address: 0x0075D970 (FUN_0075D970, cfunc_SetArmyStatsSyncArmy)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SetArmyStatsSyncArmyL`.
 */
int moho::cfunc_SetArmyStatsSyncArmy(lua_State* const luaContext)
{
  return cfunc_SetArmyStatsSyncArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075D990 (FUN_0075D990, func_SetArmyStatsSyncArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SetArmyStatsSyncArmy(army)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetArmyStatsSyncArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyStatsSyncArmy",
    &moho::cfunc_SetArmyStatsSyncArmy,
    nullptr,
    "<global>",
    kSetArmyStatsSyncArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075D9F0 (FUN_0075D9F0, cfunc_SetArmyStatsSyncArmyL)
 *
 * What it does:
 * Reads one integer and stores it in `Sim::mSyncArmy`.
 */
int moho::cfunc_SetArmyStatsSyncArmyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyStatsSyncArmyHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject armyArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    armyArg.TypeError("integer");
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  if (sim) {
    sim->mSyncArmy = static_cast<std::int32_t>(lua_tonumber(rawState, 1));
  }
  return 0;
}

/**
 * Address: 0x0075CC40 (FUN_0075CC40, func_GetUnitBlueprintByName_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetUnitBlueprintByName(bpName)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetUnitBlueprintByName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetUnitBlueprintByName",
    &moho::cfunc_GetUnitBlueprintByName,
    nullptr,
    "<global>",
    kGetUnitBlueprintByNameLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CC20 (FUN_0075CC20, cfunc_GetUnitBlueprintByName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitBlueprintByNameL`.
 */
int moho::cfunc_GetUnitBlueprintByName(lua_State* const luaContext)
{
  return cfunc_GetUnitBlueprintByNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075CCA0 (FUN_0075CCA0, cfunc_GetUnitBlueprintByNameL)
 *
 * What it does:
 * Reads one unit blueprint id string, resolves it via `Sim::mRules`, and
 * returns the blueprint Lua object (or `nil` when unresolved).
 */
int moho::cfunc_GetUnitBlueprintByNameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitBlueprintByNameHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject blueprintArg{};
  blueprintArg.m_state = state;
  blueprintArg.m_stackIndex = 1;
  const char* const blueprintName = lua_tostring(rawState, 1);
  if (blueprintName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  RRuleGameRules* const rules = sim ? sim->mRules : nullptr;
  const RUnitBlueprint* blueprint = nullptr;
  if (rules != nullptr) {
    RResId resourceId{};
    gpg::STR_InitFilename(&resourceId.name, blueprintName);
    blueprint = rules->GetUnitBlueprint(resourceId);
  }

  if (blueprint != nullptr) {
    LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
    luaBlueprint.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }
  return 1;
}

/**
 * Address: 0x0075DBA0 (FUN_0075DBA0, func_DrawLine_LuaFuncDef)
 *
 * What it does:
 * Publishes global `DrawLine(a,b,c)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_DrawLine_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DrawLine",
    &moho::cfunc_DrawLine,
    nullptr,
    "<global>",
    kDrawLineHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075DB80 (FUN_0075DB80, cfunc_DrawLine)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_DrawLineL`.
 */
int moho::cfunc_DrawLine(lua_State* const luaContext)
{
  return cfunc_DrawLineL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075DC00 (FUN_0075DC00, cfunc_DrawLineL)
 *
 * What it does:
 * Reads `(startVec3, endVec3, color)` from Lua and emits one debug line
 * segment on the current sim debug canvas.
 */
int moho::cfunc_DrawLineL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDrawLineHelpText, 3, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  CDebugCanvas* const debugCanvas = sim ? sim->GetDebugCanvas() : nullptr;
  if (!debugCanvas) {
    return 0;
  }

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 3));
  LuaPlus::LuaObject endObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject startObject(LuaPlus::LuaStackObject(state, 1));

  SDebugLine line{};
  line.p0 = SCR_FromLuaCopy<Wm3::Vector3f>(startObject);
  line.p1 = SCR_FromLuaCopy<Wm3::Vector3f>(endObject);
  line.depth0 = static_cast<std::int32_t>(SCR_DecodeColor(state, colorObject));
  line.depth1 = line.depth0;

  debugCanvas->DebugDrawLine(line);
  return 0;
}

/**
 * Address: 0x0075DDA0 (FUN_0075DDA0, cfunc_DrawLinePop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_DrawLinePopL`.
 */
int moho::cfunc_DrawLinePop(lua_State* const luaContext)
{
  return cfunc_DrawLinePopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075DDC0 (FUN_0075DDC0, func_DrawLinePop_LuaFuncDef)
 *
 * What it does:
 * Publishes global `DrawLinePop(a,b,c)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_DrawLinePop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DrawLinePop",
    &moho::cfunc_DrawLinePop,
    nullptr,
    "<global>",
    kDrawLinePopHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075DE20 (FUN_0075DE20, cfunc_DrawLinePopL)
 *
 * What it does:
 * Reads `(startVec3, endVec3, color)`, draws the line, and emits one
 * wire-circle "pop" marker just past the line end.
 */
int moho::cfunc_DrawLinePopL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDrawLinePopHelpText, 3, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  CDebugCanvas* const debugCanvas = sim ? sim->GetDebugCanvas() : nullptr;
  if (!debugCanvas) {
    return 0;
  }

  LuaPlus::LuaObject startObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject endObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 3));

  const Wm3::Vector3f start = SCR_FromLuaCopy<Wm3::Vector3f>(startObject);
  const Wm3::Vector3f end = SCR_FromLuaCopy<Wm3::Vector3f>(endObject);
  const std::uint32_t color = SCR_DecodeColor(state, colorObject);

  Wm3::Vector3f lineDirection{};
  lineDirection.x = start.x - end.x;
  lineDirection.y = start.y - end.y;
  lineDirection.z = start.z - end.z;

  const float directionLengthSquared =
    (lineDirection.x * lineDirection.x) + (lineDirection.y * lineDirection.y) + (lineDirection.z * lineDirection.z);
  if (directionLengthSquared > 0.0f) {
    const float scale = 2.0f / std::sqrt(directionLengthSquared);
    lineDirection.x *= scale;
    lineDirection.y *= scale;
    lineDirection.z *= scale;
  } else {
    lineDirection.x = 0.0f;
    lineDirection.y = 0.0f;
    lineDirection.z = 0.0f;
  }

  SDebugLine line{};
  line.p0 = start;
  line.p1 = end;
  line.depth0 = static_cast<std::int32_t>(color);
  line.depth1 = line.depth0;
  debugCanvas->DebugDrawLine(line);

  Wm3::Vector3f popCenter{};
  popCenter.x = end.x + lineDirection.x;
  popCenter.y = end.y + lineDirection.y;
  popCenter.z = end.z + lineDirection.z;

  const Wm3::Vector3f upAxis(0.0f, 1.0f, 0.0f);
  debugCanvas->AddWireCircle(upAxis, popCenter, 1.0f, color, 8u);
  return 0;
}

/**
 * Address: 0x0075E0D0 (FUN_0075E0D0, func_DrawCircle_LuaFuncDef)
 *
 * What it does:
 * Publishes global `DrawCircle(a,s,c)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_DrawCircle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DrawCircle",
    &moho::cfunc_DrawCircle,
    nullptr,
    "<global>",
    kDrawCircleHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E0B0 (FUN_0075E0B0, cfunc_DrawCircle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_DrawCircleL`.
 */
int moho::cfunc_DrawCircle(lua_State* const luaContext)
{
  return cfunc_DrawCircleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E130 (FUN_0075E130, cfunc_DrawCircleL)
 *
 * What it does:
 * Reads `(centerVec3, sizeNumber, color)` from Lua and emits one wireframe
 * debug circle on the current sim debug canvas.
 */
int moho::cfunc_DrawCircleL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDrawCircleHelpText, 3, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  CDebugCanvas* const debugCanvas = sim ? sim->GetDebugCanvas() : nullptr;
  if (!debugCanvas) {
    return 0;
  }

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 3));
  LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject sizeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&sizeArg, "number");
  }

  const float size = static_cast<float>(lua_tonumber(rawState, 2));
  const std::uint32_t color = SCR_DecodeColor(state, colorObject);
  const Wm3::Vector3f center = SCR_FromLuaCopy<Wm3::Vector3f>(centerObject);
  const Wm3::Vector3f upAxis(0.0f, 1.0f, 0.0f);
  debugCanvas->AddWireCircle(upAxis, center, size, color, 8u);
  return 0;
}

/**
 * Address: 0x0068BD90 (FUN_0068BD90, cfunc_EntityAttachTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityAttachToL`.
 */
int moho::cfunc_EntityAttachTo(lua_State* const luaContext)
{
  return cfunc_EntityAttachToL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068BE10 (FUN_0068BE10, cfunc_EntityAttachToL)
 *
 * What it does:
 * Reads `(selfEntity, parentEntity, parentBone)` and applies one attach-info
 * payload through `Entity::AttachTo`.
 */
int moho::cfunc_EntityAttachToL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAttachToHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject childObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const childEntity = SCR_FromLua_Entity(childObject, state);

  const LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const parentEntity = SCR_FromLua_Entity(parentObject, state);

  LuaPlus::LuaStackObject parentBoneArg(state, 3);
  const int parentBoneIndex = ENTSCR_ResolveBoneIndex(parentEntity, parentBoneArg, true);

  SEntAttachInfo attachInfo = SEntAttachInfo::MakeDetached();
  attachInfo.TargetWeakLink().ResetFromObject(parentEntity);
  attachInfo.mParentBoneIndex = parentBoneIndex;
  attachInfo.mChildBoneIndex = 0;
  attachInfo.mRelativeOrientX = 1.0f;
  attachInfo.mRelativeOrientY = 0.0f;
  attachInfo.mRelativeOrientZ = 0.0f;
  attachInfo.mRelativeOrientW = 0.0f;
  attachInfo.mRelativePosX = 0.0f;
  attachInfo.mRelativePosY = 0.0f;
  attachInfo.mRelativePosZ = 0.0f;

  const bool didAttach = childEntity->AttachTo(attachInfo);
  attachInfo.TargetWeakLink().UnlinkFromOwnerChain();

  if (!didAttach) {
    const char* const parentName = ResolveBlueprintIdCString(parentEntity);
    const char* const childName = ResolveBlueprintIdCString(childEntity);
    LuaPlus::LuaState::Error(
      state,
      kEntityAttachFailureError,
      childName ? childName : "",
      parentName ? parentName : "",
      parentBoneIndex
    );
  }

  return 0;
}

/**
 * Address: 0x0068BDB0 (FUN_0068BDB0, func_EntityAttachTo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:AttachTo()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityAttachTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "AttachTo",
    &moho::cfunc_EntityAttachTo,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityAttachToHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068F660 (FUN_0068F660, cfunc_EntitySetOrientation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntitySetOrientationL`.
 */
int moho::cfunc_EntitySetOrientation(lua_State* const luaContext)
{
  return cfunc_EntitySetOrientationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068F6E0 (FUN_0068F6E0, cfunc_EntitySetOrientationL)
 *
 * What it does:
 * Reads `(entity, orientation, immediate)`, writes pending orientation while
 * preserving current position, then optionally commits coords immediately.
 */
int moho::cfunc_EntitySetOrientationL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetOrientationHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 2));
  Wm3::Quatf orientation{};
  SCR_FromLuaCopy<Wm3::Quaternion<float>>(&orientationObject, &orientation);

  LuaPlus::LuaStackObject immediateArg(state, 3);
  const bool immediate = immediateArg.GetBoolean();

  VTransform transform = entity->GetTransformWm3();
  transform.orient_ = orientation;
  entity->SetPendingTransform(transform, 1.0f);
  if (immediate) {
    entity->AdvanceCoords();
    entity->AdvanceCoords();
  }
  return 0;
}

/**
 * Address: 0x0068F680 (FUN_0068F680, func_EntitySetOrientation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:SetOrientation()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntitySetOrientation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetOrientation",
    &moho::cfunc_EntitySetOrientation,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntitySetOrientationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068FA10 (FUN_0068FA10, cfunc_EntitySetPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntitySetPositionL`.
 */
int moho::cfunc_EntitySetPosition(lua_State* const luaContext)
{
  return cfunc_EntitySetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068FA90 (FUN_0068FA90, cfunc_EntitySetPositionL)
 *
 * What it does:
 * Reads `(entity, position[, immediate])`, writes pending position while
 * preserving current orientation, then optionally commits coords immediately.
 */
int moho::cfunc_EntitySetPositionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntitySetPositionHelpText,
      2,
      3,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  VTransform transform = entity->GetTransformWm3();
  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  transform.pos_ = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);
  entity->SetPendingTransform(transform, 1.0f);

  LuaPlus::LuaStackObject immediateArg(state, 3);
  if (immediateArg.GetBoolean()) {
    entity->AdvanceCoords();
    entity->AdvanceCoords();
  }
  return 0;
}

/**
 * Address: 0x0068FA30 (FUN_0068FA30, func_EntitySetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:SetPosition()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntitySetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetPosition",
    &moho::cfunc_EntitySetPosition,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntitySetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068FC10 (FUN_0068FC10, cfunc_EntityGetPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityGetPositionL`.
 */
int moho::cfunc_EntityGetPosition(lua_State* const luaContext)
{
  return cfunc_EntityGetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068FC90 (FUN_0068FC90, cfunc_EntityGetPositionL)
 *
 * What it does:
 * Reads `(entity[, boneName])` and returns one Lua vector table for the entity
 * world position or one resolved bone world position.
 */
int moho::cfunc_EntityGetPositionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntityGetPositionHelpText,
      1,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLuaNoError_Entity(entityObject);
  if (!entity) {
    const Wm3::Vec3f zeroPosition(0.0f, 0.0f, 0.0f);
    const LuaPlus::LuaObject zeroObject = SCR_ToLua<Wm3::Vector3<float>>(state, zeroPosition);
    zeroObject.PushStack(state);
    return 1;
  }

  if (lua_gettop(rawState) > 1) {
    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);
    const Wm3::Vec3f position = entity->GetBoneWorldTransform(boneIndex).pos_;
    const LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, position);
    positionObject.PushStack(state);
    return 1;
  }

  const Wm3::Vec3f position = entity->GetTransformWm3().pos_;
  LuaPlus::LuaObject& cachedPositionObject = entity->mLuaPositionCache;
  if (cachedPositionObject.IsTable()) {
    cachedPositionObject.SetNumber(1, position.x);
    cachedPositionObject.SetNumber(2, position.y);
    cachedPositionObject.SetNumber(3, position.z);
  } else {
    const LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, position);
    cachedPositionObject = positionObject;
  }

  cachedPositionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0068FC30 (FUN_0068FC30, func_EntityGetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:GetPosition()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityGetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetPosition",
    &moho::cfunc_EntityGetPosition,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityGetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068FEE0 (FUN_0068FEE0, cfunc_EntityGetPositionXYZ)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityGetPositionXYZL`.
 */
int moho::cfunc_EntityGetPositionXYZ(lua_State* const luaContext)
{
  return cfunc_EntityGetPositionXYZL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068FF60 (FUN_0068FF60, cfunc_EntityGetPositionXYZL)
 *
 * What it does:
 * Reads `(entity[, boneName])` and returns three Lua numbers `(x, y, z)` for
 * entity world position or resolved bone world position.
 */
int moho::cfunc_EntityGetPositionXYZL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntityGetPositionXYZHelpText,
      1,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  Wm3::Vec3f position{};
  if (lua_gettop(rawState) <= 1) {
    position = entity->GetTransformWm3().pos_;
  } else {
    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);
    position = entity->GetBoneWorldTransform(boneIndex).pos_;
  }

  lua_pushnumber(rawState, position.x);
  lua_pushnumber(rawState, position.y);
  lua_pushnumber(rawState, position.z);
  return 3;
}

/**
 * Address: 0x0068FF00 (FUN_0068FF00, func_EntityGetPositionXYZ_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:GetPositionXYZ()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityGetPositionXYZ_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetPositionXYZ",
    &moho::cfunc_EntityGetPositionXYZ,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityGetPositionXYZHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068CA80 (FUN_0068CA80, cfunc_EntityGetCollisionExtentsL)
 *
 * What it does:
 * Reads one entity Lua object and returns one table containing `Min` and `Max`
 * vector entries when collision extents are available.
 */
int moho::cfunc_EntityGetCollisionExtentsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetCollisionExtentsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);
  EntityCollisionUpdater* const collisionShape = entity->CollisionExtents;

  LuaPlus::LuaObject resultObject(state);
  if (collisionShape) {
    EntityCollisionBoundsScratch scratchBounds{};
    const EntityCollisionBoundsView* const bounds = collisionShape->GetBoundingBox(&scratchBounds);

    resultObject.AssignNewTable(state, 0, 0u);

    Wm3::Vector3f minBounds{};
    minBounds.x = bounds->minX;
    minBounds.y = bounds->minY;
    minBounds.z = bounds->minZ;
    const LuaPlus::LuaObject minObject = SCR_ToLua<Wm3::Vector3<float>>(state, minBounds);
    resultObject.SetObject("Min", minObject);

    Wm3::Vector3f maxBounds{};
    maxBounds.x = bounds->maxX;
    maxBounds.y = bounds->maxY;
    maxBounds.z = bounds->maxZ;
    const LuaPlus::LuaObject maxObject = SCR_ToLua<Wm3::Vector3<float>>(state, maxBounds);
    resultObject.SetObject("Max", maxObject);
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0068DE80 (FUN_0068DE80, cfunc_EntityIsIntelEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityIsIntelEnabledL`.
 */
int moho::cfunc_EntityIsIntelEnabled(lua_State* const luaContext)
{
  return cfunc_EntityIsIntelEnabledL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068DEA0 (FUN_0068DEA0, func_EntityIsIntelEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:IsIntelEnabled()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityIsIntelEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsIntelEnabled",
    &moho::cfunc_EntityIsIntelEnabled,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityIsIntelEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068DF00 (FUN_0068DF00, cfunc_EntityIsIntelEnabledL)
 *
 * What it does:
 * Reads `(entity, intelType)`, validates intel initialization, and returns one
 * Lua boolean indicating whether the selected intel lane is currently enabled.
 */
int moho::cfunc_EntityIsIntelEnabledL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityIsIntelEnabledHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityIsIntelEnabledInitWarning);
  }

  const bool enabled = entity->mIntelManager ? IsIntelEnabledForType(*entity->mIntelManager, intelType) : false;
  lua_pushboolean(rawState, enabled ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0068E050 (FUN_0068E050, cfunc_EntityEnableIntel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityEnableIntelL`.
 */
int moho::cfunc_EntityEnableIntel(lua_State* const luaContext)
{
  return cfunc_EntityEnableIntelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E070 (FUN_0068E070, func_EntityEnableIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:EnableIntel()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityEnableIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EnableIntel",
    &moho::cfunc_EntityEnableIntel,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityEnableIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E0D0 (FUN_0068E0D0, cfunc_EntityEnableIntelL)
 *
 * What it does:
 * Reads `(entity, intelType)`, enables that intel lane, and requeues the
 * entity into sim coord updates.
 */
int moho::cfunc_EntityEnableIntelL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityEnableIntelHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityEnableIntelInitWarning);
  }

  if (CIntel* const intelManager = entity->mIntelManager; intelManager != nullptr) {
    if (CIntelPosHandle* const handle = ResolveIntelPosHandleForType(*intelManager, intelType); handle != nullptr) {
      if (handle->mEnabled == 0u) {
        handle->mEnabled = 1u;
        handle->AddViz();
      }
    } else if (CIntelToggleState* const toggleState = ResolveIntelToggleStateForType(*intelManager, intelType);
               toggleState != nullptr && toggleState->present != 0u) {
      toggleState->enabled = 1u;
    }
  }

  SetEntityIntelEnabledAttributeBit(*entity, intelType, true);
  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068E2F0 (FUN_0068E2F0, cfunc_EntityDisableIntel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityDisableIntelL`.
 */
int moho::cfunc_EntityDisableIntel(lua_State* const luaContext)
{
  return cfunc_EntityDisableIntelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E310 (FUN_0068E310, func_EntityDisableIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:DisableIntel()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityDisableIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "DisableIntel",
    &moho::cfunc_EntityDisableIntel,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityDisableIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E370 (FUN_0068E370, cfunc_EntityDisableIntelL)
 *
 * What it does:
 * Reads `(entity, intelType)`, disables that intel lane, and requeues the
 * entity into sim coord updates.
 */
int moho::cfunc_EntityDisableIntelL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityDisableIntelHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityDisableIntelInitWarning);
  }

  if (CIntel* const intelManager = entity->mIntelManager; intelManager != nullptr) {
    if (CIntelPosHandle* const handle = ResolveIntelPosHandleForType(*intelManager, intelType); handle != nullptr) {
      if (handle->mEnabled != 0u) {
        handle->SubViz();
        handle->mEnabled = 0u;
      }
    } else if (CIntelToggleState* const toggleState = ResolveIntelToggleStateForType(*intelManager, intelType);
               toggleState != nullptr && toggleState->present != 0u) {
      toggleState->enabled = 0u;
    }
  }

  SetEntityIntelEnabledAttributeBit(*entity, intelType, false);
  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068E590 (FUN_0068E590, cfunc_EntitySetIntelRadius)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntitySetIntelRadiusL`.
 */
int moho::cfunc_EntitySetIntelRadius(lua_State* const luaContext)
{
  return cfunc_EntitySetIntelRadiusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E5B0 (FUN_0068E5B0, func_EntitySetIntelRadius_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:SetIntelRadius()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntitySetIntelRadius_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetIntelRadius",
    &moho::cfunc_EntitySetIntelRadius,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntitySetIntelRadiusHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E610 (FUN_0068E610, cfunc_EntitySetIntelRadiusL)
 *
 * What it does:
 * Reads `(entity, intelType, radius)`, updates intel handle radius and synced
 * intel-attribute radius, then requeues coord updates.
 */
int moho::cfunc_EntitySetIntelRadiusL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntitySetIntelRadiusHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  LuaPlus::LuaStackObject radiusArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&radiusArg, "integer");
  }

  const int inputRadius = static_cast<int>(lua_tonumber(rawState, 3));
  const int newRadius = inputRadius > 0 ? inputRadius : 0;

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntitySetIntelRadiusInitWarning);
  }

  if (CIntel* const intelManager = entity->mIntelManager; intelManager != nullptr) {
    if (CIntelPosHandle* const handle = ResolveIntelPosHandleForType(*intelManager, intelType); handle != nullptr) {
      handle->ChangeRadius(newRadius);
    }
  }

  const int attributeLane = static_cast<int>(intelType) - 1;
  if (attributeLane >= 0 && attributeLane <= 12) {
    SetEntityAttributeRangePreserveEnabledBit(
      GetEntityIntelAttributeRangesMutable(*entity), attributeLane, static_cast<std::uint32_t>(newRadius)
    );
  }

  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068E7D0 (FUN_0068E7D0, cfunc_EntityGetIntelRadius)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_EntityGetIntelRadiusL`.
 */
int moho::cfunc_EntityGetIntelRadius(lua_State* const luaContext)
{
  return cfunc_EntityGetIntelRadiusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E7F0 (FUN_0068E7F0, func_EntityGetIntelRadius_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:GetIntelRadius()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityGetIntelRadius_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetIntelRadius",
    &moho::cfunc_EntityGetIntelRadius,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityGetIntelRadiusHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068E850 (FUN_0068E850, cfunc_EntityGetIntelRadiusL)
 *
 * What it does:
 * Reads `(entity, intelType)`, validates intel initialization, and returns
 * the selected intel radius as one Lua number.
 */
int moho::cfunc_EntityGetIntelRadiusL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityGetIntelRadiusHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 2);
  const char* const intelTypeName = lua_tostring(rawState, 2);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  if (entity->mIntelManager == nullptr) {
    LuaPlus::LuaState::Error(state, kEntityGetIntelRadiusInitWarning);
  }

  const std::int32_t attributeLane = static_cast<std::int32_t>(intelType) - 1;
  std::uint32_t radius = 0u;
  if (attributeLane >= 0 && attributeLane <= 12) {
    const auto& ranges = GetEntityIntelAttributeRanges(*entity);
    radius = GetEntityAttributeRangeMagnitude(ranges, attributeLane);
  }

  lua_pushnumber(rawState, static_cast<float>(radius));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0068E9A0 (FUN_0068E9A0, cfunc_EntityInitIntel)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityInitIntelL`.
 */
int moho::cfunc_EntityInitIntel(lua_State* const luaContext)
{
  return cfunc_EntityInitIntelL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068E9C0 (FUN_0068E9C0, func_EntityInitIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:InitIntel()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityInitIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "InitIntel",
    &moho::cfunc_EntityInitIntel,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityInitIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068EA20 (FUN_0068EA20, cfunc_EntityInitIntelL)
 *
 * What it does:
 * Reads `(entity, army, intelType[, radius])`, initializes/updates one intel
 * lane, refreshes handle positions, and requeues coord updates.
 */
int moho::cfunc_EntityInitIntelL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 3 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kEntityInitIntelHelpText,
      3,
      4,
      argumentCount
    );
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    LuaPlus::LuaState::Error(state, kEntityInitIntelUnknownArmyWarning);
    return 0;
  }
  CAiReconDBImpl* const reconDb = army->GetReconDB();

  EIntel intelType = INTEL_None;
  gpg::RRef enumRef = MakeEIntelRef(&intelType);
  const LuaPlus::LuaStackObject intelTypeArg(state, 3);
  const char* const intelTypeName = lua_tostring(rawState, 3);
  if (intelTypeName == nullptr) {
    intelTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, intelTypeName, enumRef);

  int radius = 0;
  if (argumentCount == 4) {
    LuaPlus::LuaStackObject radiusArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&radiusArg, "integer");
    }

    radius = static_cast<int>(lua_tonumber(rawState, 4));
    if (static_cast<int>(intelType) > static_cast<int>(INTEL_None)
        && static_cast<int>(intelType) <= static_cast<int>(INTEL_CloakField) && radius == 0) {
      LuaPlus::LuaState::Error(state, kEntityInitIntelRadiusWarning);
    }
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  CIntel* intelManager = entity->mIntelManager;
  if (intelManager != nullptr) {
    intelManager->InitIntel(static_cast<std::int32_t>(intelType), static_cast<std::uint32_t>(radius), reconDb, sim);
  } else {
    auto* const createdIntelManager = new CIntel();
    createdIntelManager->InitIntel(static_cast<std::int32_t>(intelType), static_cast<std::uint32_t>(radius), reconDb, sim);
    entity->mIntelManager = createdIntelManager;
    intelManager = createdIntelManager;
  }

  const std::int32_t currentTick = sim->mCurTick;
  const Wm3::Vec3f position = entity->GetTransformWm3().pos_;
  for (std::size_t index = 0; index < CIntel::kHandleCount; ++index) {
    CIntelPosHandle* const handle = intelManager->mIntelHandles[index];
    if (handle != nullptr) {
      handle->UpdatePos(currentTick, position);
    }
  }

  const std::int32_t attributeLane = static_cast<std::int32_t>(intelType) - 1;
  if (attributeLane >= 0 && attributeLane <= 12) {
    SetEntityAttributeRangePreserveEnabledBit(
      GetEntityIntelAttributeRangesMutable(*entity), attributeLane, static_cast<std::uint32_t>(radius)
    );
  }

  RequeueEntityCoordUpdate(*entity);
  return 0;
}

/**
 * Address: 0x0068ED50 (FUN_0068ED50, cfunc_EntityAddShooter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityAddShooterL`.
 */
int moho::cfunc_EntityAddShooter(lua_State* const luaContext)
{
  return cfunc_EntityAddShooterL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068ED70 (FUN_0068ED70, func_EntityAddShooter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:AddShooter()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityAddShooter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "AddShooter",
    &moho::cfunc_EntityAddShooter,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityAddShooterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068EDD0 (FUN_0068EDD0, cfunc_EntityAddShooterL)
 *
 * What it does:
 * Reads `(entity, shooter)` and inserts `shooter` into the entity shooter set.
 */
int moho::cfunc_EntityAddShooterL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityAddShooterHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject shooterObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const shooter = SCR_FromLua_Entity(shooterObject, state);
  if (shooter != nullptr) {
    (void)entity->mShooters.Add(shooter);
  }

  return 0;
}

/**
 * Address: 0x0068EEC0 (FUN_0068EEC0, cfunc_EntityRemoveShooter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_EntityRemoveShooterL`.
 */
int moho::cfunc_EntityRemoveShooter(lua_State* const luaContext)
{
  return cfunc_EntityRemoveShooterL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0068EEE0 (FUN_0068EEE0, func_EntityRemoveShooter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:RemoveShooter()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityRemoveShooter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "RemoveShooter",
    &moho::cfunc_EntityRemoveShooter,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityRemoveShooterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0068EF40 (FUN_0068EF40, cfunc_EntityRemoveShooterL)
 *
 * What it does:
 * Reads `(entity, shooter)` and removes `shooter` from the entity shooter set.
 */
int moho::cfunc_EntityRemoveShooterL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityRemoveShooterHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  const LuaPlus::LuaObject shooterObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const shooter = SCR_FromLua_Entity(shooterObject, state);
  if (shooter != nullptr) {
    (void)entity->mShooters.Remove(shooter);
  }

  return 0;
}

/**
 * Address: 0x006FC3B0 (FUN_006FC3B0, cfunc_CreateProp)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreatePropL`.
 */
int moho::cfunc_CreateProp(lua_State* const luaContext)
{
  return cfunc_CreatePropL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006FC430 (FUN_006FC430, cfunc_CreatePropL)
 *
 * What it does:
 * Reads `(location, prop_blueprint_id)`, creates one prop in sim space, and
 * returns the created prop Lua object.
 */
int moho::cfunc_CreatePropL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreatePropHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 1));
  const Wm3::Vec3f location = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);

  LuaPlus::LuaStackObject blueprintArg(state, 2);
  const char* const blueprintId = lua_tostring(rawState, 2);
  if (!blueprintId) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  VTransform transform{};
  transform.pos_ = location;

  Sim* const sim = ResolveGlobalSim(rawState);
  Prop* const prop = PROP_Create(sim, transform, blueprintId);
  if (!prop) {
    LuaPlus::LuaState::Error(state, "Unable to create prop '%s'", blueprintId ? blueprintId : "");
  }

  prop->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006FC3D0 (FUN_006FC3D0, func_CreateProp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateProp`.
 */
moho::CScrLuaInitForm* moho::func_CreateProp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreateProp",
    &moho::cfunc_CreateProp,
    nullptr,
    "<global>",
    kCreatePropHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B5170 (FUN_007B5170, cfunc_CreateUnitAtMouse)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreateUnitAtMouseL`.
 */
int moho::cfunc_CreateUnitAtMouse(lua_State* const luaContext)
{
  return cfunc_CreateUnitAtMouseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B5190 (FUN_007B5190, func_CreateUnitAtMouse_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateUnitAtMouse`.
 */
moho::CScrLuaInitForm* moho::func_CreateUnitAtMouse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CreateUnitAtMouse",
    &moho::cfunc_CreateUnitAtMouse,
    nullptr,
    "<global>",
    kCreateUnitAtMouseHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B51E0 (FUN_007B51E0, cfunc_CreateUnitAtMouseL)
 *
 * What it does:
 * Reads `(blueprintId, armyIndex, offsetX, offsetZ, rotation)`, resolves one
 * unit blueprint, snaps non-mobile units to footprint-aligned map cells, and
 * submits one create-unit command through the active sim driver.
 */
int moho::cfunc_CreateUnitAtMouseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateUnitAtMouseHelpText, 5, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, "No active session.");
    return 0;
  }

  LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* const blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintText ? blueprintText : "");

  RUnitBlueprint* const blueprint = session->mRules ? session->mRules->GetUnitBlueprint(lookupId) : nullptr;
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit kind: %s", blueprintText ? blueprintText : "");
    return 0;
  }

  LuaPlus::LuaStackObject armyIndexArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&armyIndexArg, "integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));

  const int armyCount = static_cast<int>(session->userArmies.size());
  if (armyIndex < 0 || armyIndex >= armyCount) {
    LuaPlus::LuaState::Error(
      state,
      "Invalid army index, must be >= 0 and < %d but got %d.",
      armyCount,
      armyIndex
    );
    return 0;
  }

  LuaPlus::LuaStackObject offsetZArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&offsetZArg, "number");
  }
  const float offsetZ = static_cast<float>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject offsetXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&offsetXArg, "number");
  }
  const float offsetX = static_cast<float>(lua_tonumber(rawState, 3));

  SCoordsVec2 spawnPos{};
  spawnPos.x = session->CursorWorldPos.x + offsetX;
  spawnPos.z = session->CursorWorldPos.z + offsetZ;

  LuaPlus::LuaStackObject rotationArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&rotationArg, "number");
  }
  const float rotation = static_cast<float>(lua_tonumber(rawState, 5));

  if (!blueprint->IsMobile()) {
    Sim* const sim = ResolveGlobalSim(rawState);
    STIMap* const map = sim ? sim->mMapData : nullptr;
    if (map != nullptr) {
      const float anchorZ = spawnPos.z - (static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);
      const float anchorX = spawnPos.x - (static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);

      SOCellPos anchorCell{};
      anchorCell.x = static_cast<std::int16_t>(static_cast<int>(anchorX));
      anchorCell.z = static_cast<std::int16_t>(static_cast<int>(anchorZ));

      const Wm3::Vector3f alignedPos = COORDS_ToWorldPos(
        map,
        anchorCell,
        static_cast<ELayer>(blueprint->mFootprint.mOccupancyCaps),
        static_cast<int>(blueprint->mFootprint.mSizeX),
        static_cast<int>(blueprint->mFootprint.mSizeZ)
      );
      spawnPos.x = alignedPos.x;
      spawnPos.z = alignedPos.z;
    }
  }

  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (activeDriver != nullptr) {
    RResId createId{};
    gpg::STR_CopyFilename(&createId.name, &blueprint->mBlueprintId);
    activeDriver->CreateUnit(static_cast<std::uint32_t>(armyIndex), createId, spawnPos, rotation);
  }

  return 0;
}

/**
 * Address: 0x006FC590 (FUN_006FC590, cfunc_EntityCreatePropAtBone)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_EntityCreatePropAtBoneL`.
 */
int moho::cfunc_EntityCreatePropAtBone(lua_State* const luaContext)
{
  return cfunc_EntityCreatePropAtBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006FC610 (FUN_006FC610, cfunc_EntityCreatePropAtBoneL)
 *
 * What it does:
 * Reads `(entity, boneIndexOrName, propBlueprintId)` from Lua, creates a prop at
 * the resolved entity bone transform, then re-warps it using bone-local
 * compensation so the prop bone origin aligns to that entity bone.
 */
int moho::cfunc_EntityCreatePropAtBoneL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCreatePropAtBoneHelpText, 3, argumentCount);
  }

  LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneArg, false);

  LuaPlus::LuaStackObject blueprintArg(state, 3);
  const char* const blueprintId = lua_tostring(state->m_state, 3);
  if (!blueprintId) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  const VTransform entityBoneTransform = entity->GetBoneWorldTransform(boneIndex);

  Sim* const sim = entity->SimulationRef;
  Prop* const prop = PROP_Create(sim, entityBoneTransform, blueprintId);
  if (!prop) {
    LuaPlus::LuaState::Error(state, "Unable to create prop '%s'", blueprintId ? blueprintId : "");
  }

  const VTransform propBoneInverse = prop->GetBoneLocalTransform(0).Inverse();
  const VTransform alignedTransform = VTransform::Compose(propBoneInverse, entityBoneTransform);
  prop->Warp(alignedTransform);

  prop->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006FC5B0 (FUN_006FC5B0, func_EntityCreatePropAtBone_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Entity:CreatePropAtBone()` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_EntityCreatePropAtBone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreatePropAtBone",
    &moho::cfunc_EntityCreatePropAtBone,
    &CScrLuaMetatableFactory<Entity>::Instance(),
    "Entity",
    kEntityCreatePropAtBoneHelpText
  );
  return &binder;
}

/**
 * Address: 0x00547030 (FUN_00547030, cfunc_CreateResourceDeposit)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreateResourceDepositL`.
 */
int moho::cfunc_CreateResourceDeposit(lua_State* const luaContext)
{
  return cfunc_CreateResourceDepositL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005470B0 (FUN_005470B0, cfunc_CreateResourceDepositL)
 *
 * What it does:
 * Reads `(type, x, y, z, size)` from Lua, translates the deposit type string,
 * and emits one resource deposit point into sim resources.
 */
int moho::cfunc_CreateResourceDepositL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateResourceDepositHelpText, 5, argumentCount);
  }

  CSimResources* const resources = ResolveGlobalSim(state->m_state)->mSimResources.px;

  LuaPlus::LuaStackObject depositTypeArg{};
  depositTypeArg.m_state = state;
  depositTypeArg.m_stackIndex = 1;
  const char* const depositTypeText = lua_tostring(state->m_state, 1);
  if (!depositTypeText) {
    LuaPlus::LuaStackObject::TypeError(&depositTypeArg, "string");
  }

  const msvc8::string depositTypeName{depositTypeText != nullptr ? depositTypeText : ""};

  LuaPlus::LuaStackObject zArg{};
  zArg.m_state = state;
  zArg.m_stackIndex = 4;
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float posZ = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject yArg{};
  yArg.m_state = state;
  yArg.m_stackIndex = 3;
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yArg, "number");
  }
  const float posY = static_cast<float>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject xArg{};
  xArg.m_state = state;
  xArg.m_stackIndex = 2;
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }

  Wm3::Vec3f position{};
  position.x = static_cast<float>(lua_tonumber(state->m_state, 2));
  position.y = posY;
  position.z = posZ;

  LuaPlus::LuaStackObject sizeArg0{};
  sizeArg0.m_state = state;
  sizeArg0.m_stackIndex = 5;
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&sizeArg0, "integer");
  }
  const int sizeY = static_cast<int>(lua_tonumber(state->m_state, 5));

  LuaPlus::LuaStackObject sizeArg1{};
  sizeArg1.m_state = state;
  sizeArg1.m_stackIndex = 5;
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&sizeArg1, "integer");
  }

  Wm3::Vec2i size{};
  size.x = static_cast<int>(lua_tonumber(state->m_state, 5));
  size.y = sizeY;

  static msvc8::string resourceDepositTypeNames[3] = {
    msvc8::string(""),
    msvc8::string("Mass"),
    msvc8::string("Hydrocarbon"),
  };

  msvc8::string* const match =
    moho::SearchStringArrayFor(resourceDepositTypeNames, resourceDepositTypeNames + 3, &depositTypeName);
  const int depositTypeIndex =
    match != resourceDepositTypeNames + 3 ? static_cast<int>(match - resourceDepositTypeNames) : 0;

  if (depositTypeIndex == 0) {
    gpg::Logf(kUnknownResourceDepositTypeMessage, depositTypeName.c_str());
  }

  resources->AddDepositPoint(static_cast<EDepositType>(depositTypeIndex), &position, &size);
  return 1;
}

/**
 * Address: 0x00547050 (FUN_00547050, func_CreateResourceDeposit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateResourceDeposit`.
 */
moho::CScrLuaInitForm* moho::func_CreateResourceDeposit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreateResourceDeposit",
    &moho::cfunc_CreateResourceDeposit,
    nullptr,
    "<global>",
    kCreateResourceDepositHelpText
  );
  return &binder;
}

/**
 * Address: 0x0128B884 (FUN_0128B884, cfunc_GetDepositsAroundPoint)
 *
 * What it does:
 * Reads `(x, z, radius, type)` from Lua and returns an array of deposits:
 * `{ x1, z1, x2, z2, type, dist }`.
 */
int moho::cfunc_GetDepositsAroundPoint(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const float x = static_cast<float>(lua_tonumber(luaContext, 1));
  const float z = static_cast<float>(lua_tonumber(luaContext, 2));
  const float radius = static_cast<float>(lua_tonumber(luaContext, 3));
  const float nanGuard = x + z + radius;
  if (nanGuard != nanGuard) {
    return 0;
  }

  const auto type = static_cast<EDepositType>(static_cast<int>(lua_tonumber(luaContext, 4)));

  lua_newtable(luaContext);

  Sim* const sim = ResolveGlobalSim(luaContext);
  CSimResources* const resources = sim ? sim->mSimResources.px : nullptr;
  if (!resources) {
    return 1;
  }

  gpg::fastvector<ResourceDepositDistance> nearbyDeposits{};
  resources->GetDepositsAroundPoint(x, z, radius, type, &nearbyDeposits);

  for (std::size_t i = 0; i < nearbyDeposits.size(); ++i) {
    const ResourceDepositDistance& hit = nearbyDeposits[i];
    const ResourceDeposit& deposit = hit.deposit;

    lua_pushnumber(luaContext, static_cast<lua_Number>(i + 1u));
    lua_newtable(luaContext);
    LuaPushNumberField(luaContext, "x1", deposit.footprintRect.x0);
    LuaPushNumberField(luaContext, "z1", deposit.footprintRect.z0);
    LuaPushNumberField(luaContext, "x2", deposit.footprintRect.x1);
    LuaPushNumberField(luaContext, "z2", deposit.footprintRect.z1);
    LuaPushNumberField(luaContext, "type", static_cast<int>(deposit.depositType));
    LuaPushNumberField(luaContext, "dist", hit.centerDistance);
    lua_settable(luaContext, -3);
  }

  return 1;
}

/**
 * Address: 0x0128BB27 (FUN_0128BB27, cfunc_SessionIsReplaySim)
 *
 * What it does:
 * Pushes whether the current world session is in replay mode.
 */
int moho::cfunc_SessionIsReplaySim(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const CWldSession* const session = WLD_GetActiveSession();
  lua_pushboolean(luaContext, (session && session->IsReplay) ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0128BBFC (FUN_0128BBFC, cfunc_SetFocusArmySim)
 *
 * What it does:
 * Reads focus-army index from Lua arg #1 and writes the pending driver focus lane.
 */
int moho::cfunc_SetFocusArmySim(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const int focusArmy = static_cast<int>(lua_tonumber(luaContext, 1));

  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver()) {
    if (auto* const simDriver = dynamic_cast<CSimDriver*>(activeDriver)) {
      simDriver->SetPendingFocusArmyRaw(focusArmy);
    } else {
      activeDriver->SetArmyIndex(focusArmy);
    }
  }

  return 0;
}

/**
 * Address: 0x0128BB51 (FUN_0128BB51, cfunc_SetCommandSourceSim)
 *
 * What it does:
 * Reads `(armyIndex, sourceIndex, enabled)` from Lua args and toggles the
 * corresponding bit in `CArmyImpl::MohoSetValidCommandSources`.
 */
int moho::cfunc_SetCommandSourceSim(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const std::int32_t armyIndex = static_cast<std::int32_t>(lua_tonumber(luaContext, 1));
  const std::int32_t sourceIndex = static_cast<std::int32_t>(lua_tonumber(luaContext, 2));
  const bool enabled = lua_toboolean(luaContext, 3) != 0;

  Sim* const sim = ResolveGlobalSim(luaContext);
  if (!sim || armyIndex < 0 || static_cast<std::size_t>(armyIndex) >= sim->mArmiesList.size()) {
    return 0;
  }

  CArmyImpl* const army = sim->mArmiesList[static_cast<std::size_t>(armyIndex)];
  if (!army || !army->MohoSetValidCommandSources.items_begin) {
    return 0;
  }

  SetArmyValidCommandSourceBit(*army, sourceIndex, enabled);
  return 0;
}

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

  CollisionResultFastVectorN10 hits{};
  mOGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr) {
      continue;
    }
    if (unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }
    if (unit->mCurrentLayer != LAYER_Land && unit->mCurrentLayer != LAYER_Seabed) {
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
    return army ? army->ArmyId : -1;
  }

  return -1;
}

/**
 * Address: 0x007080B0 (FUN_007080B0, cfunc_ShouldCreateInitialArmyUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ShouldCreateInitialArmyUnitsL`.
 */
int moho::cfunc_ShouldCreateInitialArmyUnits(lua_State* const luaContext)
{
  return cfunc_ShouldCreateInitialArmyUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007080D0 (FUN_007080D0, func_ShouldCreateInitialArmyUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ShouldCreateInitialArmyUnits`.
 */
moho::CScrLuaInitForm* moho::func_ShouldCreateInitialArmyUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ShouldCreateInitialArmyUnits",
    &moho::cfunc_ShouldCreateInitialArmyUnits,
    nullptr,
    "<global>",
    kShouldCreateInitialArmyUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708130 (FUN_00708130, cfunc_ShouldCreateInitialArmyUnitsL)
 *
 * What it does:
 * Returns one Lua boolean indicating whether startup should spawn initial army
 * units (disabled by `/noinitialunits`).
 */
int moho::cfunc_ShouldCreateInitialArmyUnitsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kShouldCreateInitialArmyUnitsHelpText, 0, argumentCount);
  }

  const bool disableInitialUnits = CFG_GetArgOption("/noinitialunits", 0u, nullptr);
  lua_pushboolean(state->m_state, !disableInitialUnits);
  return 1;
}

/**
 * Address: 0x007081A0 (FUN_007081A0, cfunc_ListArmies)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ListArmiesL`.
 */
int moho::cfunc_ListArmies(lua_State* const luaContext)
{
  return cfunc_ListArmiesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007081C0 (FUN_007081C0, func_ListArmies_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ListArmies`.
 */
moho::CScrLuaInitForm* moho::func_ListArmies_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ListArmies",
    &moho::cfunc_ListArmies,
    nullptr,
    "<global>",
    kListArmiesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708220 (FUN_00708220, cfunc_ListArmiesL)
 *
 * What it does:
 * Returns one Lua array table containing army names in simulation order.
 */
int moho::cfunc_ListArmiesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kListArmiesHelpText, 0, argumentCount);
  }

  Sim* const sim = SIM_FromLuaState(state);
  LuaPlus::LuaObject armiesTable(state);
  armiesTable.AssignNewTable(state, 0, 0u);

  if (sim != nullptr) {
    for (std::size_t armyIndex = 0; armyIndex < sim->mArmiesList.size(); ++armyIndex) {
      CArmyImpl* const army = sim->mArmiesList[armyIndex];
      const char* const armyName = (army && army->ArmyName.c_str()) ? army->ArmyName.c_str() : "";
      armiesTable.SetString(static_cast<std::int32_t>(armyIndex + 1u), armyName);
    }
  }

  armiesTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x00708310 (FUN_00708310, cfunc_GetArmyBrain)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetArmyBrainL`.
 */
int moho::cfunc_GetArmyBrain(lua_State* const luaContext)
{
  return cfunc_GetArmyBrainL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708330 (FUN_00708330, func_GetArmyBrain_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyBrain`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyBrain_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetArmyBrain",
    &moho::cfunc_GetArmyBrain,
    nullptr,
    "<global>",
    kGetArmyBrainHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708390 (FUN_00708390, cfunc_GetArmyBrainL)
 *
 * What it does:
 * Resolves one army selector and pushes that army brain Lua object.
 */
int moho::cfunc_GetArmyBrainL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyBrainHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CScriptObject* const brainScriptObject = reinterpret_cast<CScriptObject*>(army->GetArmyBrain());
  brainScriptObject->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00708460 (FUN_00708460, cfunc_SetArmyStart)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyStartL`.
 */
int moho::cfunc_SetArmyStart(lua_State* const luaContext)
{
  return cfunc_SetArmyStartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708480 (FUN_00708480, func_SetArmyStart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyStart`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyStart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyStart",
    &moho::cfunc_SetArmyStart,
    nullptr,
    "<global>",
    kSetArmyStartHelpText
  );
  return &binder;
}

/**
 * Address: 0x007084E0 (FUN_007084E0, cfunc_SetArmyStartL)
 *
 * What it does:
 * Reads `(army, x, z)` from Lua and forwards one start-position vector to
 * `CArmyImpl::SetArmyStart`.
 */
int moho::cfunc_SetArmyStartL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyStartHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }

  LuaPlus::LuaStackObject zArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }

  Wm3::Vector2f startPosition{};
  startPosition.x = static_cast<float>(lua_tonumber(state->m_state, 2));
  startPosition.y = static_cast<float>(lua_tonumber(state->m_state, 3));
  army->SetArmyStart(startPosition);
  return 0;
}

/**
 * Address: 0x007085E0 (FUN_007085E0, cfunc_GenerateArmyStart)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GenerateArmyStartL`.
 */
int moho::cfunc_GenerateArmyStart(lua_State* const luaContext)
{
  return cfunc_GenerateArmyStartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708600 (FUN_00708600, func_GenerateArmyStart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GenerateArmyStart`.
 */
moho::CScrLuaInitForm* moho::func_GenerateArmyStart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GenerateArmyStart",
    &moho::cfunc_GenerateArmyStart,
    nullptr,
    "<global>",
    kGenerateArmyStartHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708660 (FUN_00708660, cfunc_GenerateArmyStartL)
 *
 * What it does:
 * Reads one army selector and forwards start generation to `CArmyImpl`.
 */
int moho::cfunc_GenerateArmyStartL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGenerateArmyStartHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  army->GenerateArmyStart();
  return 0;
}

/**
 * Address: 0x00708970 (FUN_00708970, cfunc_ArmyInitializePrebuiltUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_ArmyInitializePrebuiltUnitsL`.
 */
int moho::cfunc_ArmyInitializePrebuiltUnits(lua_State* const luaContext)
{
  return cfunc_ArmyInitializePrebuiltUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708990 (FUN_00708990, func_ArmyInitializePrebuiltUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyInitializePrebuiltUnits`.
 */
moho::CScrLuaInitForm* moho::func_ArmyInitializePrebuiltUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyInitializePrebuiltUnits",
    &moho::cfunc_ArmyInitializePrebuiltUnits,
    nullptr,
    "<global>",
    kArmyInitializePrebuiltUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x007089F0 (FUN_007089F0, cfunc_ArmyInitializePrebuiltUnitsL)
 *
 * What it does:
 * Reads one army selector and runs `OnSpawnPreBuiltUnits` on that army's
 * brain script object.
 */
int moho::cfunc_ArmyInitializePrebuiltUnitsL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kArmyInitializePrebuiltUnitsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiBrain* const brain = army->GetArmyBrain();
  reinterpret_cast<CScriptObject*>(brain)->OnSpawnPreBuiltUnits();
  return 0;
}

/**
 * Address: 0x007090A0 (FUN_007090A0, cfunc_SetIgnoreArmyUnitCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_SetIgnoreArmyUnitCapL`.
 */
int moho::cfunc_SetIgnoreArmyUnitCap(lua_State* const luaContext)
{
  return cfunc_SetIgnoreArmyUnitCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007090C0 (FUN_007090C0, func_SetIgnoreArmyUnitCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetIgnoreArmyUnitCap`.
 */
moho::CScrLuaInitForm* moho::func_SetIgnoreArmyUnitCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetIgnoreArmyUnitCap",
    &moho::cfunc_SetIgnoreArmyUnitCap,
    nullptr,
    "<global>",
    kSetIgnoreArmyUnitCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709120 (FUN_00709120, cfunc_SetIgnoreArmyUnitCapL)
 *
 * What it does:
 * Reads `(army, flag)` from Lua and updates unit-cap ignore mode through the
 * army interface.
 */
int moho::cfunc_SetIgnoreArmyUnitCapL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetIgnoreArmyUnitCapHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  LuaPlus::LuaStackObject flagArg(state, 2);
  const bool useUnitCap = flagArg.GetBoolean();
  army->SetUseUnitCap(useUnitCap);
  return 0;
}

/**
 * Address: 0x007091B0 (FUN_007091B0, cfunc_SetIgnorePlayableRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_SetIgnorePlayableRectL`.
 */
int moho::cfunc_SetIgnorePlayableRect(lua_State* const luaContext)
{
  return cfunc_SetIgnorePlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007091D0 (FUN_007091D0, func_SetIgnorePlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetIgnorePlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SetIgnorePlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetIgnorePlayableRect",
    &moho::cfunc_SetIgnorePlayableRect,
    nullptr,
    "<global>",
    kSetIgnorePlayableRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709230 (FUN_00709230, cfunc_SetIgnorePlayableRectL)
 *
 * What it does:
 * Reads `(army, flag)` from Lua and updates playable-rect ignore mode through
 * the army interface.
 */
int moho::cfunc_SetIgnorePlayableRectL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetIgnorePlayableRectHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  LuaPlus::LuaStackObject flagArg(state, 2);
  const bool ignorePlayableRect = flagArg.GetBoolean();
  army->SetIgnorePlayableRect(ignorePlayableRect);
  return 0;
}

/**
 * Address: 0x007099C0 (FUN_007099C0, cfunc_IsAllySim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsAllySimL`.
 */
int moho::cfunc_IsAllySim(lua_State* const luaContext)
{
  return cfunc_IsAllySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007099E0 (FUN_007099E0, func_IsAllySim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsAlly`.
 */
moho::CScrLuaInitForm* moho::func_IsAllySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsAlly",
    &moho::cfunc_IsAllySim,
    nullptr,
    "<global>",
    kIsAllySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709A40 (FUN_00709A40, cfunc_IsAllySimL)
 *
 * What it does:
 * Reads `(army1, army2)` and returns whether army1 treats army2 as allied.
 */
int moho::cfunc_IsAllySimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsAllySimHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  const bool isAlly = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->Allies.Contains(static_cast<std::uint32_t>(secondArmy->ArmyId));
  lua_pushboolean(rawState, isAlly ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00709AF0 (FUN_00709AF0, cfunc_IsEnemySim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsEnemySimL`.
 */
int moho::cfunc_IsEnemySim(lua_State* const luaContext)
{
  return cfunc_IsEnemySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709B10 (FUN_00709B10, func_IsEnemySim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsEnemy`.
 */
moho::CScrLuaInitForm* moho::func_IsEnemySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsEnemy",
    &moho::cfunc_IsEnemySim,
    nullptr,
    "<global>",
    kIsEnemySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709B70 (FUN_00709B70, cfunc_IsEnemySimL)
 *
 * What it does:
 * Reads `(army1, army2)` and returns whether army1 treats army2 as enemy.
 */
int moho::cfunc_IsEnemySimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsEnemySimHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  const bool isEnemy = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->Enemies.Contains(static_cast<std::uint32_t>(secondArmy->ArmyId));
  lua_pushboolean(rawState, isEnemy ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00709C20 (FUN_00709C20, cfunc_IsNeutralSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsNeutralSimL`.
 */
int moho::cfunc_IsNeutralSim(lua_State* const luaContext)
{
  return cfunc_IsNeutralSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709C40 (FUN_00709C40, func_IsNeutralSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsNeutral`.
 */
moho::CScrLuaInitForm* moho::func_IsNeutralSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsNeutral",
    &moho::cfunc_IsNeutralSim,
    nullptr,
    "<global>",
    kIsNeutralSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709CA0 (FUN_00709CA0, cfunc_IsNeutralSimL)
 *
 * What it does:
 * Reads `(army1, army2)` and returns whether army1 treats army2 as neutral.
 */
int moho::cfunc_IsNeutralSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsNeutralSimHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr
    && IsArmyMarkedNeutral(static_cast<std::uint32_t>(secondArmy->ArmyId), firstArmy->Neutrals);
  lua_pushboolean(rawState, isNeutral ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00709D50 (FUN_00709D50, cfunc_ArmyIsCivilian)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ArmyIsCivilianL`.
 */
int moho::cfunc_ArmyIsCivilian(lua_State* const luaContext)
{
  return cfunc_ArmyIsCivilianL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709D70 (FUN_00709D70, func_ArmyIsCivilian_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyIsCivilian`.
 */
moho::CScrLuaInitForm* moho::func_ArmyIsCivilian_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyIsCivilian",
    &moho::cfunc_ArmyIsCivilian,
    nullptr,
    "<global>",
    kArmyIsCivilianHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709DD0 (FUN_00709DD0, cfunc_ArmyIsCivilianL)
 *
 * What it does:
 * Returns whether the selected army is civilian.
 */
int moho::cfunc_ArmyIsCivilianL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kArmyIsCivilianHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushboolean(rawState, (army != nullptr && army->IsCivilian != 0u) ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00709FB0 (FUN_00709FB0, cfunc_SetArmyFactionIndex)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyFactionIndexL`.
 */
int moho::cfunc_SetArmyFactionIndex(lua_State* const luaContext)
{
  return cfunc_SetArmyFactionIndexL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709FD0 (FUN_00709FD0, func_SetArmyFactionIndex_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyFactionIndex`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyFactionIndex_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyFactionIndex",
    &moho::cfunc_SetArmyFactionIndex,
    nullptr,
    "<global>",
    kSetArmyFactionIndexHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A030 (FUN_0070A030, cfunc_SetArmyFactionIndexL)
 *
 * What it does:
 * Reads `(army, index)` and updates the army faction index lane.
 */
int moho::cfunc_SetArmyFactionIndexL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyFactionIndexHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject factionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    factionArg.TypeError("integer");
  }

  if (army != nullptr) {
    army->FactionIndex = static_cast<std::int32_t>(lua_tonumber(rawState, 2));
  }
  return 0;
}

/**
 * Address: 0x0070A920 (FUN_0070A920, cfunc_OkayToMessWithArmy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_OkayToMessWithArmyL`.
 */
int moho::cfunc_OkayToMessWithArmy(lua_State* const luaContext)
{
  return cfunc_OkayToMessWithArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A940 (FUN_0070A940, func_OkayToMessWithArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `OkayToMessWithArmy`.
 */
moho::CScrLuaInitForm* moho::func_OkayToMessWithArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "OkayToMessWithArmy",
    &moho::cfunc_OkayToMessWithArmy,
    nullptr,
    "<global>",
    kOkayToMessWithArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A9A0 (FUN_0070A9A0, cfunc_OkayToMessWithArmyL)
 *
 * What it does:
 * Returns true when current command source is valid for that army or cheats
 * are enabled.
 */
int moho::cfunc_OkayToMessWithArmyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kOkayToMessWithArmyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  bool allowed = false;
  if (army != nullptr && army->IsOutOfGame == 0u) {
    Sim* const sim = army->GetSim();
    if (sim != nullptr) {
      const int commandSource = sim->mCurCommandSource;
      allowed = commandSource != static_cast<int>(kInvalidCommandSource) &&
        army->MohoSetValidCommandSources.Contains(static_cast<std::uint32_t>(commandSource));
      if (!allowed) {
        allowed = sim->CheatsEnabled();
      }
    }
  }

  lua_pushboolean(rawState, allowed ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0070AA60 (FUN_0070AA60, cfunc_ArmyIsOutOfGame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ArmyIsOutOfGameL`.
 */
int moho::cfunc_ArmyIsOutOfGame(lua_State* const luaContext)
{
  return cfunc_ArmyIsOutOfGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070AA80 (FUN_0070AA80, func_ArmyIsOutOfGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyIsOutOfGame`.
 */
moho::CScrLuaInitForm* moho::func_ArmyIsOutOfGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyIsOutOfGame",
    &moho::cfunc_ArmyIsOutOfGame,
    nullptr,
    "<global>",
    kArmyIsOutOfGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070AAE0 (FUN_0070AAE0, cfunc_ArmyIsOutOfGameL)
 *
 * What it does:
 * Returns whether the selected army has been marked out-of-game.
 */
int moho::cfunc_ArmyIsOutOfGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kArmyIsOutOfGameHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushboolean(rawState, (army != nullptr && army->IsOutOfGame != 0u) ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0070AB60 (FUN_0070AB60, cfunc_SetArmyOutOfGame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyOutOfGameL`.
 */
int moho::cfunc_SetArmyOutOfGame(lua_State* const luaContext)
{
  return cfunc_SetArmyOutOfGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070AB80 (FUN_0070AB80, func_SetArmyOutOfGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyOutOfGame`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyOutOfGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyOutOfGame",
    &moho::cfunc_SetArmyOutOfGame,
    nullptr,
    "<global>",
    kSetArmyOutOfGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070ABE0 (FUN_0070ABE0, cfunc_SetArmyOutOfGameL)
 *
 * What it does:
 * Marks one selected army as out-of-game.
 */
int moho::cfunc_SetArmyOutOfGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyOutOfGameHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (army != nullptr) {
    army->IsOutOfGame = 1u;
  }
  return 0;
}

/**
 * Address: 0x00709590 (FUN_00709590, cfunc_SetAlliance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetAllianceL`.
 */
int moho::cfunc_SetAlliance(lua_State* const luaContext)
{
  return cfunc_SetAllianceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007095B0 (FUN_007095B0, func_SetAlliance_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetAlliance`.
 */
moho::CScrLuaInitForm* moho::func_SetAlliance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetAlliance",
    &moho::cfunc_SetAlliance,
    nullptr,
    "<global>",
    kSetAllianceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709610 (FUN_00709610, cfunc_SetAllianceL)
 *
 * What it does:
 * Reads `(army1, army2, relation)` and writes symmetric alliance relation
 * lanes on both armies.
 */
int moho::cfunc_SetAllianceL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAllianceHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);

  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  EAlliance alliance = ALLIANCE_Neutral;
  gpg::RRef enumRef = MakeEAllianceRef(&alliance);
  const LuaPlus::LuaStackObject allianceArg(state, 3);
  const char* allianceText = lua_tostring(rawState, 3);
  if (allianceText == nullptr) {
    allianceArg.TypeError("string");
    allianceText = "";
  }
  SCR_GetEnum(state, allianceText, enumRef);

  const std::uint32_t secondArmyId = secondArmy ? static_cast<std::uint32_t>(secondArmy->ArmyId) : 0u;
  firstArmy->SetAlliance(secondArmyId, static_cast<int>(alliance));

  const std::uint32_t firstArmyId = firstArmy ? static_cast<std::uint32_t>(firstArmy->ArmyId) : 0u;
  secondArmy->SetAlliance(firstArmyId, static_cast<int>(alliance));
  return 0;
}

/**
 * Address: 0x00709720 (FUN_00709720, cfunc_SetAllianceOneWay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetAllianceOneWayL`.
 */
int moho::cfunc_SetAllianceOneWay(lua_State* const luaContext)
{
  return cfunc_SetAllianceOneWayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709740 (FUN_00709740, func_SetAllianceOneWay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetAllianceOneWay`.
 */
moho::CScrLuaInitForm* moho::func_SetAllianceOneWay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetAllianceOneWay",
    &moho::cfunc_SetAllianceOneWay,
    nullptr,
    "<global>",
    kSetAllianceOneWayHelpText
  );
  return &binder;
}

/**
 * Address: 0x007097A0 (FUN_007097A0, cfunc_SetAllianceOneWayL)
 *
 * What it does:
 * Reads `(army1, army2, relation)` and writes one-way alliance relation on
 * the first army only.
 */
int moho::cfunc_SetAllianceOneWayL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAllianceOneWayHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);

  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  EAlliance alliance = ALLIANCE_Neutral;
  gpg::RRef enumRef = MakeEAllianceRef(&alliance);
  const LuaPlus::LuaStackObject allianceArg(state, 3);
  const char* allianceText = lua_tostring(rawState, 3);
  if (allianceText == nullptr) {
    allianceArg.TypeError("string");
    allianceText = "";
  }
  SCR_GetEnum(state, allianceText, enumRef);

  const std::uint32_t secondArmyId = secondArmy ? static_cast<std::uint32_t>(secondArmy->ArmyId) : 0u;
  firstArmy->SetAlliance(secondArmyId, static_cast<int>(alliance));
  return 0;
}

/**
 * Address: 0x007098A0 (FUN_007098A0, cfunc_SetAlliedVictory)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetAlliedVictoryL`.
 */
int moho::cfunc_SetAlliedVictory(lua_State* const luaContext)
{
  return cfunc_SetAlliedVictoryL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007098C0 (FUN_007098C0, func_SetAlliedVictory_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetAlliedVictory`.
 */
moho::CScrLuaInitForm* moho::func_SetAlliedVictory_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetAlliedVictory",
    &moho::cfunc_SetAlliedVictory,
    nullptr,
    "<global>",
    kSetAlliedVictoryHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709920 (FUN_00709920, cfunc_SetAlliedVictoryL)
 *
 * What it does:
 * Reads `(army, enabled)` and updates `RequestingAlliedVictory` on that army's
 * brain script object.
 */
int moho::cfunc_SetAlliedVictoryL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAlliedVictoryHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiBrain* const brain = army ? army->GetArmyBrain() : nullptr;
  if (brain == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject enabledArg(state, 2);
  brain->mLuaObj.SetBoolean("RequestingAlliedVictory", enabledArg.GetBoolean());
  return 0;
}

/**
 * Address: 0x00708A70 (FUN_00708A70, cfunc_ArmyGetHandicap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ArmyGetHandicapL`.
 */
int moho::cfunc_ArmyGetHandicap(lua_State* const luaContext)
{
  return cfunc_ArmyGetHandicapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708A90 (FUN_00708A90, func_ArmyGetHandicap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ArmyGetHandicap`.
 */
moho::CScrLuaInitForm* moho::func_ArmyGetHandicap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "ArmyGetHandicap",
    &moho::cfunc_ArmyGetHandicap,
    nullptr,
    "<global>",
    kArmyGetHandicapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708AF0 (FUN_00708AF0, cfunc_ArmyGetHandicapL)
 *
 * What it does:
 * Resolves one army selector and returns configured handicap or zero.
 */
int moho::cfunc_ArmyGetHandicapL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kArmyGetHandicapHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  float handicap = 0.0f;
  if (army->HasHandicap != 0.0f) {
    handicap = army->Handicap;
  }
  lua_pushnumber(state->m_state, handicap);
  return 1;
}

/**
 * Address: 0x00708B90 (FUN_00708B90, cfunc_SetArmyEconomy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyEconomyL`.
 */
int moho::cfunc_SetArmyEconomy(lua_State* const luaContext)
{
  return cfunc_SetArmyEconomyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708BB0 (FUN_00708BB0, func_SetArmyEconomy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyEconomy`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyEconomy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyEconomy",
    &moho::cfunc_SetArmyEconomy,
    nullptr,
    "<global>",
    kSetArmyEconomyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708C10 (FUN_00708C10, cfunc_SetArmyEconomyL)
 *
 * What it does:
 * Reads `(army, mass, energy)` and adds those deltas to the army stored
 * economy pair.
 */
int moho::cfunc_SetArmyEconomyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyEconomyHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CSimArmyEconomyInfo* const economyInfo = army ? army->GetEconomy() : nullptr;
  if (!economyInfo) {
    return 0;
  }

  LuaPlus::LuaStackObject massArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    massArg.TypeError("number");
  }
  const float massDelta = static_cast<float>(lua_tonumber(state->m_state, 2));

  LuaPlus::LuaStackObject energyArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    energyArg.TypeError("number");
  }
  const float energyDelta = static_cast<float>(lua_tonumber(state->m_state, 3));

  economyInfo->economy.mStored.MASS += massDelta;
  economyInfo->economy.mStored.ENERGY += energyDelta;
  return 0;
}

/**
 * Address: 0x00708D60 (FUN_00708D60, cfunc_GetArmyUnitCostTotal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetArmyUnitCostTotalL`.
 */
int moho::cfunc_GetArmyUnitCostTotal(lua_State* const luaContext)
{
  return cfunc_GetArmyUnitCostTotalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708D80 (FUN_00708D80, func_GetArmyUnitCostTotal_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyUnitCostTotal`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyUnitCostTotal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetArmyUnitCostTotal",
    &moho::cfunc_GetArmyUnitCostTotal,
    nullptr,
    "<global>",
    kGetArmyUnitCostTotalHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708DE0 (FUN_00708DE0, cfunc_GetArmyUnitCostTotalL)
 *
 * What it does:
 * Resolves one army selector and returns the army total unit cost as a Lua
 * number.
 */
int moho::cfunc_GetArmyUnitCostTotalL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyUnitCostTotalHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushnumber(state->m_state, army ? army->GetArmyUnitCostTotal() : 0.0f);
  return 1;
}

/**
 * Address: 0x00708E60 (FUN_00708E60, cfunc_GetArmyUnitCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetArmyUnitCapL`.
 */
int moho::cfunc_GetArmyUnitCap(lua_State* const luaContext)
{
  return cfunc_GetArmyUnitCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708E80 (FUN_00708E80, func_GetArmyUnitCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyUnitCap`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyUnitCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetArmyUnitCap",
    &moho::cfunc_GetArmyUnitCap,
    nullptr,
    "<global>",
    kGetArmyUnitCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708EE0 (FUN_00708EE0, cfunc_GetArmyUnitCapL)
 *
 * What it does:
 * Resolves one army selector and returns that army's unit-cap value as a Lua
 * number.
 */
int moho::cfunc_GetArmyUnitCapL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyUnitCapHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushnumber(state->m_state, army->GetUnitCap());
  return 1;
}

/**
 * Address: 0x00708F70 (FUN_00708F70, cfunc_SetArmyUnitCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyUnitCapL`.
 */
int moho::cfunc_SetArmyUnitCap(lua_State* const luaContext)
{
  return cfunc_SetArmyUnitCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708F90 (FUN_00708F90, func_SetArmyUnitCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyUnitCap`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyUnitCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyUnitCap",
    &moho::cfunc_SetArmyUnitCap,
    nullptr,
    "<global>",
    kSetArmyUnitCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708FF0 (FUN_00708FF0, cfunc_SetArmyUnitCapL)
 *
 * What it does:
 * Reads `(army, unitCap)` from Lua and updates that army's unit-cap lane.
 */
int moho::cfunc_SetArmyUnitCapL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyUnitCapHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject unitCapArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    unitCapArg.TypeError("number");
  }

  const float unitCap = static_cast<float>(lua_tonumber(state->m_state, 2));
  army->SetUnitCap(unitCap);
  return 0;
}

/**
 * Address: 0x0070A180 (FUN_0070A180, cfunc_SetArmyAIPersonalityL)
 *
 * What it does:
 * Reads `(army, personality)` from Lua and updates the army personality lane.
 */
int moho::cfunc_SetArmyAIPersonalityL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyAIPersonalityHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    return 0;
  }

  LuaPlus::LuaStackObject personalityArg(state, 2);
  const char* personalityName = lua_tostring(state->m_state, 2);
  if (!personalityName) {
    LuaPlus::LuaStackObject::TypeError(&personalityArg, "string");
    personalityName = "";
  }

  if (personalityName[0] != '\0') {
    army->ArmyTypeText.assign(personalityName, 0U, msvc8::string::npos);
  }
  return 0;
}

/**
 * Address: 0x0070A100 (FUN_0070A100, cfunc_SetArmyAIPersonality)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyAIPersonalityL`.
 */
int moho::cfunc_SetArmyAIPersonality(lua_State* const luaContext)
{
  return cfunc_SetArmyAIPersonalityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A120 (FUN_0070A120, func_SetArmyAIPersonality_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyAIPersonality`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyAIPersonality_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyAIPersonality",
    &moho::cfunc_SetArmyAIPersonality,
    nullptr,
    "<global>",
    kSetArmyAIPersonalityHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A5E0 (FUN_0070A5E0, cfunc_SetArmyShowScore)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyShowScoreL`.
 */
int moho::cfunc_SetArmyShowScore(lua_State* const luaContext)
{
  return cfunc_SetArmyShowScoreL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A600 (FUN_0070A600, func_SetArmyShowScore_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyShowScore`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyShowScore_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyShowScore",
    &moho::cfunc_SetArmyShowScore,
    nullptr,
    "<global>",
    kSetArmyShowScoreHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A660 (FUN_0070A660, cfunc_SetArmyShowScoreL)
 *
 * What it does:
 * Reads `(army, showScore)` and stores score visibility in the army runtime
 * variable lane.
 */
int moho::cfunc_SetArmyShowScoreL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyShowScoreHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject showScoreArg(state, 2);
  const bool showScore = showScoreArg.GetBoolean();
  if (army != nullptr) {
    army->ShowScoreFlag = showScore ? 1u : 0u;
  }
  return 0;
}

/**
 * Address: 0x007086D0 (FUN_007086D0, cfunc_SetArmyPlans)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyPlansL`.
 */
int moho::cfunc_SetArmyPlans(lua_State* const luaContext)
{
  return cfunc_SetArmyPlansL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708750 (FUN_00708750, cfunc_SetArmyPlansL)
 *
 * What it does:
 * Reads `(army, plans)` from Lua and forwards the plans string to
 * `CArmyImpl::SetArmyPlans`.
 */
int moho::cfunc_SetArmyPlansL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyPlansHelpText, 2, argumentCount);
  }

  const char* plansText = "";
  if (lua_isstring(state->m_state, 2)) {
    const LuaPlus::LuaStackObject plansArg(state, 2);
    plansText = lua_tostring(state->m_state, 2);
    if (plansText == nullptr) {
      plansArg.TypeError("string");
    }
  }

  const msvc8::string plansValue(plansText ? plansText : "");
  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  army->SetArmyPlans(plansValue);
  return 0;
}

/**
 * Address: 0x007086F0 (FUN_007086F0, func_SetArmyPlans_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyPlans`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyPlans_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyPlans",
    &moho::cfunc_SetArmyPlans,
    nullptr,
    "<global>",
    kSetArmyPlansHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708870 (FUN_00708870, cfunc_InitializeArmyAI)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_InitializeArmyAIL`.
 */
int moho::cfunc_InitializeArmyAI(lua_State* const luaContext)
{
  return cfunc_InitializeArmyAIL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708890 (FUN_00708890, func_InitializeArmyAI_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `InitializeArmyAI`.
 */
moho::CScrLuaInitForm* moho::func_InitializeArmyAI_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "InitializeArmyAI",
    &moho::cfunc_InitializeArmyAI,
    nullptr,
    "<global>",
    kInitializeArmyAIHelpText
  );
  return &binder;
}

/**
 * Address: 0x007088F0 (FUN_007088F0, cfunc_InitializeArmyAIL)
 *
 * What it does:
 * Resolves one army selector and invokes `CAiBrain::Initialize` on that army
 * brain object.
 */
int moho::cfunc_InitializeArmyAIL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kInitializeArmyAIHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiBrain* const brain = army ? army->GetArmyBrain() : nullptr;
  if (brain != nullptr) {
    brain->Initialize();
  }
  return 0;
}

/**
 * Address: 0x0070A320 (FUN_0070A320, cfunc_SetArmyColorL)
 *
 * What it does:
 * Reads `(army, r, g, b)` from Lua and writes packed color lanes to the army.
 */
int moho::cfunc_SetArmyColorL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetArmyColorHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    return 0;
  }

  const std::uint8_t red = ReadLuaColorByteArg<2>(state);
  const std::uint8_t green = ReadLuaColorByteArg<3>(state);
  const std::uint8_t blue = ReadLuaColorByteArg<4>(state);
  const std::uint32_t packedColor = PackOpaqueArmyColor(red, green, blue);
  army->PlayerColorBgra = packedColor;
  army->ArmyColorBgra = packedColor;
  return 0;
}

/**
 * Address: 0x0070A2A0 (FUN_0070A2A0, cfunc_SetArmyColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyColorL`.
 */
int moho::cfunc_SetArmyColor(lua_State* const luaContext)
{
  return cfunc_SetArmyColorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A2C0 (FUN_0070A2C0, func_SetArmyColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyColor`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyColor",
    &moho::cfunc_SetArmyColor,
    nullptr,
    "<global>",
    kSetArmyColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074B850 (FUN_0074B850, func_EndGame_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `EndGame`.
 */
moho::CScrLuaInitForm* moho::func_EndGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EndGame",
    &moho::cfunc_EndGame,
    nullptr,
    "<global>",
    "Signal the end of the game.  Acts like a permanent pause."
  );
  return &binder;
}

/**
 * Address: 0x0074B920 (FUN_0074B920, func_IsGameOver_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `IsGameOver`.
 */
moho::CScrLuaInitForm* moho::func_IsGameOver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsGameOver",
    &moho::cfunc_IsGameOver,
    nullptr,
    "<global>",
    "Return true if the game is over (i.e. EndGame() has been called)."
  );
  return &binder;
}

/**
 * Address: 0x0074B9F0 (FUN_0074B9F0, cfunc_GetEntityById)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetEntityByIdL`.
 */
int moho::cfunc_GetEntityById(lua_State* const luaContext)
{
  return cfunc_GetEntityByIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074BA10 (FUN_0074BA10, func_GetEntityById_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetEntityById`.
 */
moho::CScrLuaInitForm* moho::func_GetEntityById_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetEntityById",
    &moho::cfunc_GetEntityById,
    nullptr,
    "<global>",
    kGetEntityByIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074BA70 (FUN_0074BA70, cfunc_GetEntityByIdL)
 *
 * What it does:
 * Resolves one string entity-id argument and returns matching entity Lua
 * object (or nil).
 */
int moho::cfunc_GetEntityByIdL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetEntityByIdHelpText, 1, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const EntId entityId = static_cast<EntId>(std::atoi(entityIdText));
  Entity* const entity = FindEntityById(sim ? sim->mEntityDB : nullptr, entityId);
  if (entity == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  entity->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0074BB40 (FUN_0074BB40, cfunc_GetUnitByIdSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitByIdSimL`.
 */
int moho::cfunc_GetUnitByIdSim(lua_State* const luaContext)
{
  return cfunc_GetUnitByIdSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074BB60 (FUN_0074BB60, func_GetUnitByIdSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetUnitById`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitByIdSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetUnitById",
    &moho::cfunc_GetUnitByIdSim,
    nullptr,
    "<global>",
    kGetUnitByIdSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074BBC0 (FUN_0074BBC0, cfunc_GetUnitByIdSimL)
 *
 * What it does:
 * Resolves one string entity-id argument and returns the matching unit Lua
 * object when that id is a unit (or nil).
 */
int moho::cfunc_GetUnitByIdSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitByIdSimHelpText, 1, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const EntId entityId = static_cast<EntId>(std::atoi(entityIdText));
  Entity* const entity = FindEntityById(sim ? sim->mEntityDB : nullptr, entityId);
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  if (unit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075C7D0 (FUN_0075C7D0, func_SetPlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetPlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SetPlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetPlayableRect",
    &moho::cfunc_SetPlayableRect,
    nullptr,
    "<global>",
    kSetPlayableRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CDD0 (FUN_0075CDD0, cfunc_GetFocusArmySim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetFocusArmySimL`.
 */
int moho::cfunc_GetFocusArmySim(lua_State* const luaContext)
{
  return cfunc_GetFocusArmySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075CDF0 (FUN_0075CDF0, func_GetFocusArmySim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetFocusArmy()` Lua binder for sim state.
 */
moho::CScrLuaInitForm* moho::func_GetFocusArmySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetFocusArmy",
    &moho::cfunc_GetFocusArmySim,
    nullptr,
    "<global>",
    kGetFocusArmySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CE50 (FUN_0075CE50, cfunc_GetFocusArmySimL)
 *
 * What it does:
 * Validates no Lua args and returns current focused army index (1-based, or
 * `-1` when unset).
 */
int moho::cfunc_GetFocusArmySimL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFocusArmySimHelpText, 0, argumentCount);
  }

  Sim* const sim = ResolveGlobalSim(state->m_state);
  int focusArmy = sim->mSyncFilter.focusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }

  lua_pushnumber(state->m_state, static_cast<float>(focusArmy));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075CEC0 (FUN_0075CEC0, cfunc_AudioSetLanguageSim)
 *
 * What it does:
 * Validates `AudioSetLanguage(name)` argument count for sim Lua lane.
 */
int moho::cfunc_AudioSetLanguageSim(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAudioSetLanguageSimHelpText, 1, argumentCount);
  }
  return 0;
}

/**
 * Address: 0x0075CF00 (FUN_0075CF00, func_AudioSetLanguageSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `AudioSetLanguage(name)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_AudioSetLanguageSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "AudioSetLanguage",
    &moho::cfunc_AudioSetLanguageSim,
    nullptr,
    "<global>",
    kAudioSetLanguageSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x008ADFF0 (FUN_008ADFF0, cfunc_AudioSetLanguageUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_AudioSetLanguageUserL`.
 */
int moho::cfunc_AudioSetLanguageUser(lua_State* const luaContext)
{
  return cfunc_AudioSetLanguageUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008AE010 (FUN_008AE010, func_AudioSetLanguageUser_LuaFuncDef)
 *
 * What it does:
 * Publishes user-lane global `AudioSetLanguage(name)` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_AudioSetLanguageUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AudioSetLanguage",
    &moho::cfunc_AudioSetLanguageUser,
    nullptr,
    "<global>",
    kAudioSetLanguageUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008AE070 (FUN_008AE070, cfunc_AudioSetLanguageUserL)
 *
 * What it does:
 * Validates one language code, then rebuilds localized voice/tutorial engines
 * when the normalized language tag changes and localized VO data exists.
 */
int moho::cfunc_AudioSetLanguageUserL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAudioSetLanguageUserHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject languageArg(state, 1);
  const char* languageText = lua_tostring(state->m_state, 1);
  if (languageText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&languageArg, "string");
    languageText = "";
  }

  const msvc8::string normalizedLanguage = gpg::STR_ToLower(languageText);
  CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
  if (userSound == nullptr) {
    return 0;
  }

  if (normalizedLanguage == userSound->mLanguageTag || !HasLocalizedVoiceDirectory(normalizedLanguage)) {
    return 0;
  }

  msvc8::string localizedRootPath = gpg::STR_Printf("/sounds/voice/%s", normalizedLanguage.c_str());
  if (AudioEngine* const voiceEngine = userSound->mTutorialEngine.get(); voiceEngine != nullptr) {
    voiceEngine->Shutdown();
  }
  userSound->mTutorialEngine = AudioEngine::Create(localizedRootPath.c_str());

  localizedRootPath.append("/tutorials");
  if (AudioEngine* const tutorialEngine = userSound->mAmbientEngine.get(); tutorialEngine != nullptr) {
    tutorialEngine->Shutdown();
  }
  userSound->mAmbientEngine = AudioEngine::Create(localizedRootPath.c_str());

  userSound->mLanguageTag.assign(normalizedLanguage, 0u, msvc8::string::npos);
  return 0;
}

/**
 * Address: 0x008AE300 (FUN_008AE300, cfunc_HasLocalizedVOUserL)
 *
 * What it does:
 * Returns whether the requested localized voice directory exists.
 */
int moho::cfunc_HasLocalizedVOUserL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kHasLocalizedVOUserHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject languageArg(state, 1);
  const char* languageText = lua_tostring(state->m_state, 1);
  if (languageText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&languageArg, "string");
    languageText = "";
  }

  const msvc8::string language(languageText);
  lua_pushboolean(state->m_state, HasLocalizedVoiceDirectory(language) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008AE280 (FUN_008AE280, cfunc_HasLocalizedVOUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_HasLocalizedVOUserL`.
 */
int moho::cfunc_HasLocalizedVOUser(lua_State* const luaContext)
{
  return cfunc_HasLocalizedVOUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008AE2A0 (FUN_008AE2A0, func_HasLocalizedVOUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `HasLocalizedVO`.
 */
moho::CScrLuaInitForm* moho::func_HasLocalizedVOUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HasLocalizedVO",
    &moho::cfunc_HasLocalizedVOUser,
    nullptr,
    "<global>",
    kHasLocalizedVOUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CF90 (FUN_0075CF90, cfunc_HasLocalizedVOSim)
 *
 * What it does:
 * Validates `HasLocalizedVO(language)` argument count on the sim Lua lane.
 */
int moho::cfunc_HasLocalizedVOSim(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kHasLocalizedVOSimHelpText, 1, argumentCount);
  }
  return 0;
}

/**
 * Address: 0x0075CFD0 (FUN_0075CFD0, func_HasLocalizedVOSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `HasLocalizedVO(language)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_HasLocalizedVOSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "HasLocalizedVO",
    &moho::cfunc_HasLocalizedVOSim,
    nullptr,
    "<global>",
    kHasLocalizedVOSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075DA80 (FUN_0075DA80, cfunc_SubmitXMLArmyStats)
 *
 * What it does:
 * Validates no args and raises the sim-side XML army-stats submit request
 * flag.
 */
int moho::cfunc_SubmitXMLArmyStats(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSubmitXMLArmyStatsHelpText, 0, argumentCount);
  }

  if (Sim* const sim = ResolveGlobalSim(state->m_state); sim != nullptr) {
    sim->mRequestXMLArmyStatsSubmit = true;
  }
  return 0;
}

/**
 * Address: 0x0075DAD0 (FUN_0075DAD0, func_SubmitXMLArmyStats_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SubmitXMLArmyStats()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_SubmitXMLArmyStats_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SubmitXMLArmyStats",
    &moho::cfunc_SubmitXMLArmyStats,
    nullptr,
    "<global>",
    kSubmitXMLArmyStatsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00761570 (FUN_00761570, cfunc_PlayLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_PlayLoopL`.
 */
int moho::cfunc_PlayLoop(lua_State* const luaContext)
{
  return cfunc_PlayLoopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00761590 (FUN_00761590, func_PlayLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes global `PlayLoop(sndParams)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_PlayLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "PlayLoop",
    &moho::cfunc_PlayLoop,
    nullptr,
    "<global>",
    kPlayLoopHelpText
  );
  return &binder;
}

/**
 * Address: 0x007615F0 (FUN_007615F0, cfunc_PlayLoopL)
 *
 * What it does:
 * Builds one `HSound` loop handle from `CSndParams`, queues it in sim sound
 * manager, binds Lua userdata, and returns the handle object.
 */
int moho::cfunc_PlayLoopL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kPlayLoopHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject sndParamsObject(LuaPlus::LuaStackObject(state, 1));
  CSndParams* const sndParams = *func_GetCObj_CSndParams(sndParamsObject);
  HSound* const sound = new HSound(sndParams);

  Sim* const sim = ResolveGlobalSim(rawState);
  if (sim != nullptr && sim->mSoundManager != nullptr) {
    (void)sim->mSoundManager->AddLoop(sound);
  }

  func_CreateLuaHSoundObject(state, sound);
  sound->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00761700 (FUN_00761700, cfunc_StopLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_StopLoopL`.
 */
int moho::cfunc_StopLoop(lua_State* const luaContext)
{
  return cfunc_StopLoopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00761720 (FUN_00761720, func_StopLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes global `StopLoop(handle)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_StopLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "StopLoop",
    &moho::cfunc_StopLoop,
    nullptr,
    "<global>",
    kStopLoopHelpText
  );
  return &binder;
}

/**
 * Address: 0x00761780 (FUN_00761780, cfunc_StopLoopL)
 *
 * What it does:
 * Resolves one `HSound` loop handle and either requests stop on sim sound
 * manager or destroys the unbound handle when no manager exists.
 */
int moho::cfunc_StopLoopL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kStopLoopHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject soundObject(LuaPlus::LuaStackObject(state, 1));
  HSound* const sound = SCR_FromLua_HSound(soundObject, state);

  Sim* const sim = ResolveGlobalSim(rawState);
  if (sim != nullptr && sim->mSoundManager != nullptr) {
    (void)sim->mSoundManager->StopLoop(sound);
    return 0;
  }

  if (sound != nullptr) {
    (void)sound->Destroy(1);
  }

  return 0;
}

gpg::RType* Sim::sType = nullptr;

namespace
{
  // Address: 0x010BA3F0 -- process-global `SimSerializer` singleton.
  SimSerializer gSimSerializer;
} // namespace

/**
 * Address: 0x00BDBC90 (FUN_00BDBC90, dynamic initializer for the global
 * `SimSerializer` singleton)
 */
SimSerializer::SimSerializer()
  : mSerLoadFunc(&SimSerializerLoadThunk)
  , mSerSaveFunc(&SimSerializerSaveThunk)
{}

/**
 * Address: 0x00C00EC0 (FUN_00C00EC0, Moho::SimSerializer::~SimSerializer)
 */
SimSerializer::~SimSerializer()
{
  ResetLinks();
}

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
 * Address: 0x007432C0 (FUN_007432C0, sub_7432C0)
 */
SimTypeInfo::~SimTypeInfo() = default;

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
   * Address: 0x008B0EB0 (FUN_008B0EB0)
   * Mangled: ?ISSUE_DecreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_DecreaseCommandCount(
   *     int a1@<ecx>, Moho::UserCommand *a2@<edi>, int a3@<esi>);
   *
   * What it does:
   * Marshals a `DecreaseCommandCount` for `helper`'s own command id through the
   * active sim driver (`sSimDriver`, vtable +0x70 at 0x008B0EBC), then records
   * the matching local decrease-count update event against the *cookie the
   * driver returned* - not the input command id - exactly as
   * `cfunc_DeleteCommandL` (0x00843FA0) does for the Lua-facing path. The
   * binary dereferences the driver global without a null test.
   *
   * `Moho::UserCommand*` is the mangled parameter type; the object is the
   * command-issue helper (`[helper+0x04]` is `mConstantData.cmd`, and the
   * update event is appended to the helper's own local ring queue).
   */
  void ISSUE_DecreaseCommandCount(UserCommandIssueHelper* const helper, const int count)
  {
    ISTIDriver* const simDriver = SIM_GetActiveDriver();
    const CmdId resultCookie = simDriver->DecreaseCommandCount(helper->mConstantData.cmd, count);
    QueueCommandIssueDecreaseCountEvent(
      reinterpret_cast<CommandIssueHelperRuntimeView&>(*helper), resultCookie, count
    );
  }

  /**
   * Address: 0x008B0180 (FUN_008B0180)
   * Mangled: ?ISSUE_Command@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_Command(gpg::fastvector<UserUnit*> const& units,
   *                                 Moho::SSTICommandIssueData data, bool clearQueue);
   *
   * What it does:
   * Client/UI-side command-issue keystone. Allocates a packed command id from
   * the active session command manager, early-outs when the id's source byte is
   * the 0xFF overflow marker, gates the issue against the focus army's no-rush
   * rules (map-playable test + no-rush radius on the XZ plane), then dispatches
   * the command to the sim driver, publishes the command-issue helper (constant
   * + variable payload), enqueues it into each selected unit's command-queue
   * manager (respecting the 500-entry depth cap and the clear flag), and finally
   * notifies the UI script layer and dirties the command graph.
   */
  void ISSUE_Command(const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData data, const bool clearQueue)
  {
    CWldSession* const session = WLD_GetActiveSession();

    // mManager == sWldSession->mSessionRes1 in the binary (0x008B01AD/+0x3FC).
    CommandManager* const commandManager = session->mCommandManager;

    // The playable-rect source at terrain-res +0x04 is the live STIMap in this
    // build; STIMap::IsPlayable is the concrete method dispatched at 0x008B030F.
    STIMap* const playableMap = reinterpret_cast<STIMap*>(session->mWldMap->mTerrainRes->mPlayableRectSource);

    // Allocate the next command id and stamp it into the issue payload.
    std::uint32_t packedCommandId = 0u;
    data.nextCommandId = static_cast<std::int32_t>(*AllocatePackedCommandIdFromManager(commandManager, &packedCommandId));
    if ((static_cast<std::uint32_t>(data.nextCommandId) & 0xFF000000u) == 0xFF000000u) {
      return; // id-pool exhausted for this command source; nothing to issue.
    }

    // No-rush / playability gate. The command is issued unless the target is a
    // concrete, valid point that violates the focus army's no-rush constraints.
    bool shouldIssue = true;
    if (data.mTarget.mType != EAiTargetType::AITARGET_None) {
      constexpr float kInvalidLane = std::numeric_limits<float>::quiet_NaN();
      Wm3::Vec3f targetPoint{kInvalidLane, kInvalidLane, kInvalidLane};

      if (data.mTarget.mType == EAiTargetType::AITARGET_Entity) {
        if (UserEntity* const targetEntity = session->LookupEntityId(static_cast<EntId>(data.mTarget.mEnt))) {
          targetPoint = targetEntity->mVariableData.mCurTransform.pos_;
        }
        // Missing entity leaves the NaN sentinel -> IsValidVector3f() is false.
      } else {
        targetPoint = data.mTarget.mPos;
      }

      const std::int32_t focusArmyIndex = session->FocusArmy;
      if (IsValidVector3f(targetPoint) && focusArmyIndex >= 0 &&
          session->userArmies[static_cast<std::size_t>(focusArmyIndex)] != nullptr) {
        const UserArmy* const focusArmy = session->GetFocusArmy();
        const bool insidePlayableArea =
          focusArmy->mVarDat.mUseWholeMap != 0u || playableMap == nullptr || playableMap->IsPlayable(targetPoint);

        if (!insidePlayableArea) {
          shouldIssue = false;
        } else if (focusArmy->mVarDat.mNoRushTimer > 0) {
          const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPoint.x;
          const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPoint.z;
          const float noRushDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
          if (noRushDistance > focusArmy->mVarDat.mNoRushRadius) {
            shouldIssue = false;
          }
        }
      }
    }

    if (!shouldIssue) {
      return; // No-rush rejection; the by-value `data` destructs on return.
    }

    // Decode the selected units into an entity-id set and dispatch to the driver.
    // NOTE: the binary callsite discards a return-by-value command cookie; the
    // recovered 3-arg driver IssueCommand returns void, so nothing is discarded.
    BVSet<EntId, EntIdUniverse> issuedEntitySet{};
    func_DecodeEntIdSet(issuedEntitySet, units);
    if (ISTIDriver* const simDriver = SIM_GetActiveDriver()) {
      simDriver->IssueCommand(issuedEntitySet, data, clearQueue);
    }

    // Publish the constant command descriptor and find/create its helper.
    SSTICommandConstantData commandConstantData{};
    InitializePublishedCommandDescriptorFromIssueData(&commandConstantData, &data);

    const std::int32_t commandId = data.nextCommandId;
    UserCommandIssueHelper* const commandHelper =
      FindOrCreateCommandIssueHelper(*commandManager, commandConstantData, 1u, commandId);

    // Overwrite the helper's variable payload from the issue data and mark dirty.
    commandHelper->mVariableData = SSTICommandVariableData(data);
    commandHelper->mVariableDataDirty = 1u;

    // Enqueue the published command into each selected unit's command manager.
    // FUN_008B0180 asm 0x008B0540-0x008B0577: the binary gates the per-unit
    // reset and the UI notification on a separate "command issued" latch
    // (ebp-4, set to 1 at 0x008B03F7 on this post-gate path), NOT on clearQueue.
    // That latch is always 1 here (the loop is only reached once the command
    // has been issued), so both the <=500 and >500 queue-size branches reset
    // the manager and then add the command -- the >500 branch reaches the
    // shared reset->add through the binary's fall-through (loc_8B055C ->
    // loc_8B0566). clearQueue (the BOOL param a2) feeds only
    // UserUnitManagerAdd's flag; UI_OnCommandIssued's bool arg is the issued
    // latch, i.e. true.
    for (UserUnit* const unit : units) {
      UserCommandQueue* const unitManager = unit->GetCommandQueue();
      if (unitManager == nullptr) {
        continue;
      }

      if (GetUserUnitManagerQueueSize(unitManager) <= 500) {
        ResetUserUnitManagerState(unitManager, commandId);
        UserUnitManagerAdd(unitManager, commandHelper, commandId, clearQueue);
      } else {
        ResetUserUnitManagerState(unitManager, commandId);
        UserUnitManagerAdd(unitManager, commandHelper, commandId, clearQueue);
      }
    }

    UI_OnCommandIssued(units, data, true);
    session->DirtyCommandGraph();
  }

namespace
{
  // Process-global `AI_DebugCollision` sim convar singleton (statically
  // constructed at .data 0x010AD5F8). When set, `Sim::DoCollisionsFor` skips
  // physical collision resolution so the collision overlay can be inspected.
  // Same fixed-address accessor pattern as `moho::console::Sim*ConVar()`.
  [[nodiscard]] CSimConVarBase* AIDebugCollisionConVar() noexcept
  {
    constexpr std::uintptr_t kAIDebugCollisionConVarEa = 0x010AD5F8u;
    return reinterpret_cast<CSimConVarBase*>(kAIDebugCollisionConVarEa);
  }

  // Owner "mass" proxy = blueprint average density folded over the unit's
  // bounding-box volume (density * sizeX * sizeY * sizeZ). Used to weight the
  // momentum split between two colliding units.
  [[nodiscard]] float BlueprintMassProxy(const RUnitBlueprint& blueprint) noexcept
  {
    return blueprint.mAverageDensity * blueprint.mSizeZ * blueprint.mSizeY * blueprint.mSizeX;
  }

  // The collision-push footprint gate: `pusher` may transfer an impulse to
  // `other` when the pusher ignores structures (FPFLAG_None), or both units are
  // non-structural footprints (both carry FPFLAG_IgnoreStructures). Mirrors the
  // two symmetric `Entity::GetFootprint().mFlags` tests in the binary
  // (asm 0x598086-0x5980B8 and 0x59813E-0x59816F).
  [[nodiscard]] bool CollisionPushAllowed(const Unit& pusher, const Unit& other) noexcept
  {
    const std::uint8_t pusherFlags = static_cast<std::uint8_t>(pusher.GetFootprint().mFlags);
    const std::uint8_t otherFlags = static_cast<std::uint8_t>(other.GetFootprint().mFlags);
    constexpr std::uint8_t kIgnoreStructures = static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures);
    return pusherFlags == static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_None) ||
      ((pusherFlags & kIgnoreStructures) != 0u && (otherFlags & kIgnoreStructures) != 0u);
  }
} // namespace

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
void Sim::DoCollisionsFor(Sim* const sim, Unit* const owner, CollisionResultFastVectorN10* const collisions)
{
  constexpr float kMinPenetration = 0.001f;      // dword_DFF0AC
  constexpr float kMinSeparationSq = 0.000001f;  // flt_DFFBE8 (1e-6)
  constexpr float kMaxSpeedFactor = 0.1f;        // dbl_E4F710+4
  constexpr float kMinPushFactor = 0.1f;         // dbl_E4F710+4 (reused as impulse-share cutoff)
  constexpr float kHalfExtentScale = 0.5f;       // flt_E4F724

  // Debug/dead/queued/naval short-circuits (asm 0x597CE4-0x597D26).
  if (ReadSimConVarBool(sim, AIDebugCollisionConVar(), false) || owner->mIsNaval || owner->IsDead() ||
      owner->DestroyQueued()) {
    return;
  }

  // Owner mass proxy + a per-owner approach-speed factor: the larger of
  // (blueprint MaxSpeed * 0.1) and the current velocity magnitude
  // (asm 0x597D33-0x597DDA). MaxSpeed lives at blueprint Physics.MaxSpeed.
  const RUnitBlueprint* const ownerBlueprint = owner->GetBlueprint();
  const float ownerMass = BlueprintMassProxy(*ownerBlueprint);

  const Wm3::Vec3f ownerVelocity = owner->GetVelocity();
  const float ownerSpeed =
    std::sqrt((ownerVelocity.x * ownerVelocity.x) + (ownerVelocity.y * ownerVelocity.y) +
      (ownerVelocity.z * ownerVelocity.z));
  const float maxSpeedShare = ownerBlueprint->Physics.MaxSpeed * kMaxSpeedFactor;
  const float approachSpeed = (maxSpeedShare > ownerSpeed) ? maxSpeedShare : ownerSpeed;

  for (const CollisionResult& hit : *collisions) {
    // Skip shallow contacts and empty records (asm 0x597E2D-0x597E4A).
    if (hit.penetrationDepth < kMinPenetration) {
      continue;
    }
    Entity* const contact = hit.sourceEntity;
    if (contact == nullptr) {
      continue;
    }

    // Props receive their OnCollision Lua callback (self, owner, dir, depth);
    // the "otherObject" argument is the raw first-arg (Sim) slot the binary
    // reinterprets as a LuaObject (asm 0x597E50-0x597E9A + FUN_00598660). This
    // is an original-source type-pun; reproduce it exactly for 1:1 behavior.
    if (contact->IsProp() != nullptr) {
      contact->RunScriptOnCollision(
        *reinterpret_cast<const LuaPlus::LuaObject*>(sim),
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
    pushDir.x = owner->PrevPosition.x - candidatePos.x;
    pushDir.y = 0.0f;
    pushDir.z = owner->PrevPosition.z - candidatePos.z;

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
    float pushMagnitude = maxFootprintDim * kHalfExtentScale;
    if (hit.penetrationDepth > pushMagnitude) {
      pushMagnitude = hit.penetrationDepth;
    }
    pushMagnitude += approachSpeed;

    // Mass-weighted momentum split (asm 0x598031-0x59807A):
    //   candidateShare = ownerMass / (ownerMass + candidateMass)
    //   ownerShare     = 1 - candidateShare
    // A heavier owner claims a larger candidateShare, shoving the candidate
    // more while itself yielding less. The two AddImpulse branches below apply
    // these complementary shares.
    const float candidateMass = BlueprintMassProxy(*candidate->GetBlueprint());
    const float candidateShare = ownerMass / (candidateMass + ownerMass);
    const float ownerShare = 1.0f - candidateShare;

    // Owner impulse (asm 0x598080-0x59811F): pushes the owner away from the
    // candidate, scaled by pushMagnitude and the owner's share.
    if (ownerShare > kMinPushFactor && CollisionPushAllowed(*owner, *candidate) &&
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
    if (candidateShare > kMinPushFactor && CollisionPushAllowed(*candidate, *owner) &&
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

  CollisionResultFastVectorN10 hits{};
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
        const msvc8::vector<WeakPtr<CUnitCommand>>& commands = queue->mCommandVec;
        if (commands.empty()) {
          idle = true;
        } else {
          const WeakPtr<CUnitCommand>& head = commands.data()[0];
          idle = (head.ownerLinkSlot == nullptr) || head.IsSentinel();
        }
      }
      if (!idle) {
        continue;
      }
    }

    if (unit->mCurrentLayer == LAYER_Air) {
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
    if (blocker.mCurrentLayer == LAYER_Water) {
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

    const int dirMaskX = (x1 < x2) ? -1 : 0;
    const float p0x = (dirMaskX != 0) ? -x2 : x2;  // cursorX origin (blocker)
    const float p0z = (dirMaskX != 0) ? -x1 : x1;  // xLimit (far)
    const int dirMaskZ = (z1 < z2) ? -1 : 0;
    const float p0y = (dirMaskZ != 0) ? -z2 : z2;  // cursorZ origin (far)
    const float p1x = (dirMaskZ != 0) ? -z1 : z1;  // zLimit (blocker)

    const float extentX = p0z - p0x;
    const float extentZ = p1x - p0y;
    int cursorX = static_cast<int>(std::floor(p0x));
    int cursorZ = static_cast<int>(std::floor(p0y));

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
          const float cellX = pos.x + static_cast<float>(col * ringStep);
          const float cellZ = pos.z + static_cast<float>(row * ringStep);
          if (TryDisplacementCell(sim, oGrid, blocker, footprint, buildRect, cellX, cellZ, outRect)) {
            return true;
          }
        }
      }
    }
    return false;
  }
} // namespace

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

  CollisionResultFastVectorN10 hits{};
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
      unit->mIsAir || (Wm3::Vector3f::Compare(&unit->Position, &unit->PrevPosition) == 0);
    if (!airOrAtRest || unit->mCurrentLayer == LAYER_Air || unit->IsDead()) {
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
    if (Wm3::Vector3f::Compare(&delta, &zeroVec) == 0) {
      unitDirX = 0.0f;
      unitDirZ = 1.0f;
    } else {
      const float len = std::sqrt((dirX * dirX) + (dirZ * dirZ));
      if (len <= 0.000001f) {
        unitDirX = 0.0f;
        unitDirZ = 0.0f;
      } else {
        unitDirX = dirX / len;
        unitDirZ = dirZ / len;
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
    blocker->SimulationRef->mOGrid->mOccupation.FillRect(
      placedRect.x0, placedRect.z0, placedRect.x1 - placedRect.x0, placedRect.z1 - placedRect.z0, true);

    if (IAiNavigator* const navigator = blocker->AiNavigator) {
      const SOCellPos goalCell{static_cast<std::int16_t>(placedRect.x0), static_cast<std::int16_t>(placedRect.z0)};
      const SNavGoal goal{goalCell};
      navigator->SetGoal(goal);
    }
  }
}
} // namespace moho


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
      (void)::moho::func_ParseEntityCategoryUser_LuaFuncDef();
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
      (void)::moho::func_GetUnitCommandFromCommandCap_LuaFuncDef();
      (void)::moho::func_EjectSessionClient_LuaFuncDef();
      (void)::moho::func_WorldIsLoading_LuaFuncDef();
      (void)::moho::func_WorldIsPlaying_LuaFuncDef();
      (void)::moho::func_GetGameSpeed_LuaFuncDef();
      (void)::moho::func_SetGameSpeed_LuaFuncDef();
      (void)::moho::func_AddToSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_RemoveFromSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_ClearSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_CurrentTime_LuaFuncDef();
      (void)::moho::func_GameTime_LuaFuncDef();
      (void)::moho::func_GameTick_LuaFuncDef();
      (void)::moho::func_IsAllyUser_LuaFuncDef();
      (void)::moho::func_IsEnemyUser_LuaFuncDef();
      (void)::moho::func_IsNeutral_LuaFuncDef();
      (void)::moho::func_SyncPlayableRect_LuaFuncDef();
      (void)::moho::func_RandomUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryContainsUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterDownUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterOut_LuaFuncDef();
      (void)::moho::func_BlueprintLoaderUpdateProgress_LuaFuncDef();
      (void)::moho::func_RegisterBeamBlueprint_LuaFuncDef();
      (void)::moho::func_ExecLuaInSim_LuaFuncDef();
      (void)::moho::func_SimCallback_LuaFuncDef();
      (void)::moho::func_SetAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_ToggleScriptBit_LuaFuncDef();
      (void)::moho::func_SetPaused_LuaFuncDef();
      (void)::moho::func_GetAttachedUnitsList_LuaFuncDef();
      (void)::moho::func_ValidateUnitsList_LuaFuncDef();
      (void)::moho::func_GetAssistingUnitsList_LuaFuncDef();
      (void)::moho::func_GetArmyAvatars_LuaFuncDef();
      (void)::moho::func_GetIdleEngineers_LuaFuncDef();
      (void)::moho::func_GetIdleFactories_LuaFuncDef();
      (void)::moho::func_GetSelectedUnits_LuaFuncDef();
      (void)::moho::func_GetValidAttackingUnits_LuaFuncDef();
      (void)::moho::func_SelectUnits_LuaFuncDef();
      (void)::moho::func_AddSelectUnits_LuaFuncDef();
      (void)::moho::func_EngineStartSplashScreens_LuaFuncDef();
      (void)::moho::func_EngineStartFrontEndUI_LuaFuncDef();
      (void)::moho::func_ExitApplication_LuaFuncDef();
      (void)::moho::func_ExitGame_LuaFuncDef();
      (void)::moho::func_RestartSession_LuaFuncDef();
      (void)::moho::func_GetFrame_LuaFuncDef();
      (void)::moho::func_ClearFrame_LuaFuncDef();
      (void)::moho::func_GetNumRootFrames_LuaFuncDef();
      (void)::moho::func_GetEconomyTotals_LuaFuncDef();
      (void)::moho::func_GetResourceSharing_LuaFuncDef();
      (void)::moho::func_GetCurrentUIState_LuaFuncDef();
      (void)::moho::func_GetSimTicksPerSecond_LuaFuncDef();
      (void)::moho::func_SessionRequestPause_LuaFuncDef();
      (void)::moho::func_SessionResume_LuaFuncDef();
      (void)::moho::func_SessionIsPaused_LuaFuncDef();
      (void)::moho::func_SessionIsGameOver_LuaFuncDef();
      (void)::moho::func_SessionGetLocalCommandSource_LuaFuncDef();
      (void)::moho::func_SessionIsReplayUser_LuaFuncDef();
      (void)::moho::func_SessionIsBeingRecorded_LuaFuncDef();
      (void)::moho::func_SessionIsMultiplayer_LuaFuncDef();
      (void)::moho::func_SessionIsObservingAllowed_LuaFuncDef();
      (void)::moho::func_SessionCanRestart_LuaFuncDef();
      (void)::moho::func_SessionIsActive_LuaFuncDef();
      (void)::moho::func_SessionGetScenarioInfo_LuaFuncDef();
      (void)::moho::func_GetMouseWorldPosUser_LuaFuncDef();
      (void)::moho::func_GetMouseScreenPos_LuaFuncDef();
      (void)::moho::func_SetFocusArmyUser_LuaFuncDef();
      (void)::moho::func_SetInvertMidMouseButton_LuaFuncDef();
      (void)::moho::func_GetFocusArmyUser_LuaFuncDef();
      (void)::moho::func_IsObserver_LuaFuncDef();
      (void)::moho::func_GetGameTime_LuaFuncDef();
      (void)::moho::func_GetGameTimeSecondsUser_LuaFuncDef();
      (void)::moho::func_GetSystemTime_LuaFuncDef();
      (void)::moho::func_GetSystemTimeSeconds_LuaFuncDef();
      (void)::moho::func_FormatTime_LuaFuncDef();
      (void)::moho::func_GetSimRate_LuaFuncDef();
      (void)::moho::func_GetArmiesTable_LuaFuncDef();
      (void)::moho::func_GetArmyScore_LuaFuncDef();
      (void)::moho::func_DeleteCommand_LuaFuncDef();
      (void)::moho::func_GetSpecialFiles_LuaFuncDef();
      (void)::moho::func_GetSpecialFilePath_LuaFuncDef();
      (void)::moho::func_GetSpecialFolder_LuaFuncDef();
      (void)::moho::func_RemoveSpecialFile_LuaFuncDef();
      (void)::moho::func_GetSpecialFileInfo_LuaFuncDef();
      (void)::moho::func_RemoveProfileDirectories_LuaFuncDef();
      (void)::moho::func_CopyCurrentReplay_LuaFuncDef();
      (void)::moho::func_SetOverlayFilters_LuaFuncDef();
      (void)::moho::func_GenerateBuildTemplateFromSelection_LuaFuncDef();
      (void)::moho::func_ClearBuildTemplates_LuaFuncDef();
      (void)::moho::func_RenderOverlayMilitary_LuaFuncDef();
      (void)::moho::func_RenderOverlayIntel_LuaFuncDef();
      (void)::moho::func_RenderOverlayEconomy_LuaFuncDef();
      (void)::moho::func_TeamColorMode_LuaFuncDef();
      (void)::moho::func_GetUnitByIdUser_LuaFuncDef();
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
      (void)::moho::func_CreateUnitAtMouse_LuaFuncDef();
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
      (void)::moho::func_AudioSetLanguageUser_LuaFuncDef();
      (void)::moho::func_HasLocalizedVOUser_LuaFuncDef();
      (void)::moho::func_HasLocalizedVOSim_LuaFuncDef();
      (void)::moho::func_SubmitXMLArmyStats_LuaFuncDef();
      (void)::moho::func_PlayLoop_LuaFuncDef();
      (void)::moho::func_StopLoop_LuaFuncDef();
    }
  };

  const SimLuaFuncDefBootstrap gSimLuaFuncDefBootstrap{};
} // namespace
