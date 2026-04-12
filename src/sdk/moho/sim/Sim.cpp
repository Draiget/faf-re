#include "Sim.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "SimDriver.h"

#include <algorithm>
#include <array>
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
#include "moho/audio/AudioEngine.h"
#include "moho/audio/CUserSoundManager.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/command/CCommandDb.h"
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
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SParticleBuffer.h"
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
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"
#include "moho/resource/RResId.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldSession.h"
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

using namespace moho;
using EntId = std::int32_t;

std::uint8_t moho::ren_Steering = 0;
bool moho::sim_KeepAllLogFiles = false;

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

    static void* sm_eventTable[1];

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

void* moho::WRefEditDialog::sm_eventTable[1] = {nullptr};

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
  return sm_eventTable;
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
  constexpr const char* kKernel32ModuleName = "kernel32.dll";
  constexpr const char* kVirtualProtectExportName = "VirtualProtect";
  constexpr std::uint32_t kIntelRadiusMagnitudeMask = 0x7FFFFFFFu;
  constexpr std::uint32_t kIntelEnabledFlagMask = ~kIntelRadiusMagnitudeMask;
  constexpr std::size_t kEntityIntelAttributesOffset = 0x128u;
  constexpr std::size_t kDiscardClientSlotCount = 17u;
  constexpr SIZE_T kInvertMidMousePatchSize = 0x9u;
  constexpr std::uintptr_t kLuaCallbackDispatchBlockedFlagEa = 0x011FD23Fu;
  constexpr std::uintptr_t kInvertMidMouseOpcodeXEa = 0x0086E01Fu;
  constexpr std::uintptr_t kInvertMidMouseOpcodeYEa = 0x0086E027u;

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
    entity.mCoordNode.ListLinkBefore(&entity.SimulationRef->mCoordEntities);
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

  [[nodiscard]] std::uint8_t ResolveMiddleMousePatchOpcode(const bool invert) noexcept
  {
    return invert ? std::uint8_t{0x29u} : std::uint8_t{0x01u};
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

  using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

  void PatchMiddleMouseScrubOpcode(const bool invert)
  {
    const HMODULE kernel32Module = ::GetModuleHandleA(kKernel32ModuleName);
    auto* const virtualProtect = kernel32Module != nullptr
                                   ? reinterpret_cast<VirtualProtectFn>(
                                       ::GetProcAddress(kernel32Module, kVirtualProtectExportName)
                                     )
                                   : nullptr;
    if (virtualProtect == nullptr) {
      return;
    }

    auto* const patchBaseAddress = reinterpret_cast<LPVOID>(kInvertMidMouseOpcodeXEa);
    DWORD oldProtect = 0;
    if (!virtualProtect(patchBaseAddress, kInvertMidMousePatchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
      return;
    }

    const std::uint8_t opcode = ResolveMiddleMousePatchOpcode(invert);
    *reinterpret_cast<volatile std::uint8_t*>(kInvertMidMouseOpcodeXEa) = opcode;
    *reinterpret_cast<volatile std::uint8_t*>(kInvertMidMouseOpcodeYEa) = opcode;

    DWORD ignoredProtect = 0;
    virtualProtect(patchBaseAddress, kInvertMidMousePatchSize, oldProtect, &ignoredProtect);
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
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] CScrLuaInitFormSet& CoreLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("core"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("core");
    return fallbackSet;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("user"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("user");
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
    return unit ? reinterpret_cast<IUnit*>(unit->mIUnitAndScriptBridge) : nullptr;
  }

  [[nodiscard]] const IUnit* ResolveIUnitBridge(const UserUnit* const unit) noexcept
  {
    return unit ? reinterpret_cast<const IUnit*>(unit->mIUnitAndScriptBridge) : nullptr;
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

  [[nodiscard]] const UserEntityWeakSetRuntimeView* ResolveIdleUnitSetView(
    const UserArmy* const army,
    const bool useFactorySet
  ) noexcept
  {
    if (army == nullptr) {
      return nullptr;
    }

    const auto* const runtimeView = reinterpret_cast<const UserArmyIdleSetsRuntimeView*>(army);
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

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const rawState = userDataObject.GetActiveCState();
    if (!rawState) {
      return out;
    }

    const int top = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(rawState);

    void* const rawUserData = lua_touserdata(rawState, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }

    lua_settop(rawState, top);
    return out;
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
    static_assert(
      offsetof(CategoryWordRangeView, mStartWordIndex) == 0x08,
      "CategoryWordRangeView::mStartWordIndex offset must be 0x08"
    );
    return *reinterpret_cast<const BVIntSet*>(&range.mStartWordIndex);
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
    outSelectionIds.mFirstWordIndex = sim.mSyncFilter.maskB.rawWord;
    outSelectionIds.mWords.ResetFrom(sim.mSyncFilter.maskB.masks);
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

  struct CommandDbMapNodeView
  {
    CommandDbMapNodeView* left;   // +0x00
    CommandDbMapNodeView* parent; // +0x04
    CommandDbMapNodeView* right;  // +0x08
    std::uint32_t key;            // +0x0C
    CUnitCommand* value;          // +0x10
    std::uint8_t color;           // +0x14 (0 = red, 1 = black)
    std::uint8_t isNil;           // +0x15 (1 = head/sentinel)
    std::uint8_t reserved16[2];   // +0x16
  };
  static_assert(sizeof(CommandDbMapNodeView) == 0x18, "CommandDbMapNodeView size must be 0x18");
  static_assert(offsetof(CommandDbMapNodeView, key) == 0x0C, "CommandDbMapNodeView::key offset must be 0x0C");
  static_assert(offsetof(CommandDbMapNodeView, value) == 0x10, "CommandDbMapNodeView::value offset must be 0x10");
  static_assert(offsetof(CommandDbMapNodeView, color) == 0x14, "CommandDbMapNodeView::color offset must be 0x14");
  static_assert(offsetof(CommandDbMapNodeView, isNil) == 0x15, "CommandDbMapNodeView::isNil offset must be 0x15");

  struct CommandDbMapStorageView
  {
    void* proxy;                 // +0x00
    CommandDbMapNodeView* head;  // +0x04
    std::uint32_t size;          // +0x08
  };
  static_assert(sizeof(CommandDbMapStorageView) == 0x0C, "CommandDbMapStorageView size must be 0x0C");

  struct CCommandDbRuntimeView
  {
    // Binary-faithful view used by FUN_006E0EC0 lift:
    // map at +0x04, IdPool at +0x10, pending released-id vector at +0xCC0.
    Sim* sim;                                   // +0x0000
    CommandDbMapStorageView map;                // +0x0004
    IdPool pool;                                // +0x0010
    msvc8::vector<CmdId> pendingReleasedCmdIds; // +0x0CC0
  };
  static_assert(sizeof(msvc8::vector<CmdId>) == 0x10, "msvc8::vector<CmdId> size must be 0x10");
  static_assert(offsetof(CCommandDbRuntimeView, map) == 0x04, "CCommandDbRuntimeView::map offset must be 0x04");
  static_assert(offsetof(CCommandDbRuntimeView, pool) == 0x10, "CCommandDbRuntimeView::pool offset must be 0x10");
  static_assert(
    offsetof(CCommandDbRuntimeView, pendingReleasedCmdIds) == 0xCC0,
    "CCommandDbRuntimeView::pendingReleasedCmdIds offset must be 0xCC0"
  );
  static_assert(sizeof(CCommandDbRuntimeView) == 0xCD0, "CCommandDbRuntimeView size must be 0xCD0");

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

  struct SessionCommandManagerRuntimeView
  {
    std::uint8_t pad_0000_0CB4[0xCB4];
    CommandDbMapStorageView commandIssueMap; // +0x0CB4
  };
  static_assert(
    offsetof(SessionCommandManagerRuntimeView, commandIssueMap) == 0xCB4,
    "SessionCommandManagerRuntimeView::commandIssueMap offset must be 0xCB4"
  );

  static_assert(
    offsetof(SimSubRes3, mValue) == offsetof(BVIntSet, mFirstWordIndex), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(
    offsetof(SimSubRes3, mReserved04) == offsetof(BVIntSet, mReservedMetaWord), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(offsetof(SimSubRes3, mValues) == offsetof(BVIntSet, mWords), "SimSubRes3/BVIntSet offset mismatch");
  static_assert(sizeof(SimSubRes3) == sizeof(BVIntSet), "SimSubRes3/BVIntSet size mismatch");

  constexpr std::uint8_t kTreeRed = 0;
  constexpr std::uint8_t kTreeBlack = 1;

  [[nodiscard]]
  BVIntSet& AsBitSet(SimSubRes3& slot) noexcept
  {
    return *reinterpret_cast<BVIntSet*>(&slot);
  }

  [[nodiscard]]
  CommandDbMapNodeView* TreeMinNode(CommandDbMapNodeView* node, CommandDbMapNodeView* head) noexcept
  {
    while (node->left != head) {
      node = node->left;
    }
    return node;
  }

  [[nodiscard]]
  CommandDbMapNodeView* TreeMaxNode(CommandDbMapNodeView* node, CommandDbMapNodeView* head) noexcept
  {
    while (node->right != head) {
      node = node->right;
    }
    return node;
  }

  [[nodiscard]]
  std::uint8_t NodeColor(const CommandDbMapNodeView* node, const CommandDbMapNodeView* head) noexcept
  {
    if (!node || node == head) {
      return kTreeBlack;
    }
    return node->color;
  }

  void RotateLeft(CommandDbMapStorageView& map, CommandDbMapNodeView* node)
  {
    CommandDbMapNodeView* const head = map.head;
    CommandDbMapNodeView* const pivot = node->right;

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

  void RotateRight(CommandDbMapStorageView& map, CommandDbMapNodeView* node)
  {
    CommandDbMapNodeView* const head = map.head;
    CommandDbMapNodeView* const pivot = node->left;

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

  void ReplaceTreeNode(CommandDbMapStorageView& map, CommandDbMapNodeView* oldNode, CommandDbMapNodeView* newNode)
  {
    CommandDbMapNodeView* const head = map.head;
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

  void RefreshTreeBounds(CommandDbMapStorageView& map)
  {
    CommandDbMapNodeView* const head = map.head;
    if (!head) {
      return;
    }

    CommandDbMapNodeView* const root = head->parent;
    if (!root || root == head || root->isNil != 0u) {
      head->parent = head;
      head->left = head;
      head->right = head;
      return;
    }

    head->left = TreeMinNode(root, head);
    head->right = TreeMaxNode(root, head);
  }

  void EraseFixup(
    CommandDbMapStorageView& map, CommandDbMapNodeView* node, CommandDbMapNodeView* nodeParent
  )
  {
    CommandDbMapNodeView* const head = map.head;

    while (node != head->parent && NodeColor(node, head) == kTreeBlack) {
      if (node == nodeParent->left) {
        CommandDbMapNodeView* sibling = nodeParent->right;
        if (NodeColor(sibling, head) == kTreeRed) {
          sibling->color = kTreeBlack;
          nodeParent->color = kTreeRed;
          RotateLeft(map, nodeParent);
          sibling = nodeParent->right;
        }

        if (sibling == head) {
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->left, head) == kTreeBlack && NodeColor(sibling->right, head) == kTreeBlack) {
          sibling->color = kTreeRed;
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->right, head) == kTreeBlack) {
          if (sibling->left != head) {
            sibling->left->color = kTreeBlack;
          }
          sibling->color = kTreeRed;
          RotateRight(map, sibling);
          sibling = nodeParent->right;
        }

        sibling->color = nodeParent->color;
        nodeParent->color = kTreeBlack;
        if (sibling->right != head) {
          sibling->right->color = kTreeBlack;
        }
        RotateLeft(map, nodeParent);
      } else {
        CommandDbMapNodeView* sibling = nodeParent->left;
        if (NodeColor(sibling, head) == kTreeRed) {
          sibling->color = kTreeBlack;
          nodeParent->color = kTreeRed;
          RotateRight(map, nodeParent);
          sibling = nodeParent->left;
        }

        if (sibling == head) {
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->right, head) == kTreeBlack && NodeColor(sibling->left, head) == kTreeBlack) {
          sibling->color = kTreeRed;
          node = nodeParent;
          nodeParent = nodeParent->parent;
          continue;
        }

        if (NodeColor(sibling->left, head) == kTreeBlack) {
          if (sibling->right != head) {
            sibling->right->color = kTreeBlack;
          }
          sibling->color = kTreeRed;
          RotateLeft(map, sibling);
          sibling = nodeParent->left;
        }

        sibling->color = nodeParent->color;
        nodeParent->color = kTreeBlack;
        if (sibling->left != head) {
          sibling->left->color = kTreeBlack;
        }
        RotateRight(map, nodeParent);
      }

      node = head->parent;
      break;
    }

    if (node != head) {
      node->color = kTreeBlack;
    }
  }

  /**
   * Address: 0x006E1670 (FUN_006E1670, sub_6E1670)
   *
   * What it does:
   * Removes one command-id node from the command DB map and rebalances the RB-tree.
   */
  void EraseCommandNode(CommandDbMapStorageView& map, CommandDbMapNodeView* node)
  {
    CommandDbMapNodeView* const head = map.head;
    CommandDbMapNodeView* y = node;
    CommandDbMapNodeView* x = head;
    CommandDbMapNodeView* xParent = head;
    std::uint8_t yColor = y->color;

    if (node->left == head) {
      x = node->right;
      xParent = node->parent;
      ReplaceTreeNode(map, node, node->right);
    } else if (node->right == head) {
      x = node->left;
      xParent = node->parent;
      ReplaceTreeNode(map, node, node->left);
    } else {
      y = TreeMinNode(node->right, head);
      yColor = y->color;
      x = y->right;
      if (y->parent == node) {
        xParent = y;
      } else {
        xParent = y->parent;
        ReplaceTreeNode(map, y, y->right);
        y->right = node->right;
        y->right->parent = y;
      }

      ReplaceTreeNode(map, node, y);
      y->left = node->left;
      y->left->parent = y;
      y->color = node->color;
    }

    if (yColor == kTreeBlack) {
      EraseFixup(map, x, xParent);
    }

    ::operator delete(node);
    if (map.size != 0u) {
      --map.size;
    }
    RefreshTreeBounds(map);
  }

  /**
   * Address: 0x006E1940 (FUN_006E1940, sub_6E1940)
   *
   * What it does:
   * Returns the exact command-id node in a command-id map view, or the
   * head/sentinel when absent.
   */
  [[nodiscard]] const CommandDbMapNodeView* FindCommandNode(const CommandDbMapStorageView& map, const CmdId cmdId)
  {
    CommandDbMapNodeView* const head = map.head;
    if (!head) {
      return nullptr;
    }

    const std::uint32_t key = static_cast<std::uint32_t>(cmdId);
    CommandDbMapNodeView* result = head;
    CommandDbMapNodeView* node = head->parent;
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

  [[nodiscard]] CommandDbMapNodeView* FindCommandNode(CommandDbMapStorageView& map, const CmdId cmdId)
  {
    return const_cast<CommandDbMapNodeView*>(FindCommandNode(static_cast<const CommandDbMapStorageView&>(map), cmdId));
  }

  [[nodiscard]] const CommandDbMapNodeView* FindCommandNode(const CCommandDbRuntimeView& commandDb, const CmdId cmdId)
  {
    return FindCommandNode(commandDb.map, cmdId);
  }

  [[nodiscard]] CommandDbMapNodeView* FindCommandNode(CCommandDbRuntimeView& commandDb, const CmdId cmdId)
  {
    return FindCommandNode(commandDb.map, cmdId);
  }

  [[nodiscard]] CommandIssueHelperRuntimeView* FindCommandIssueHelper(CWldSession* const session, const CmdId cmdId)
  {
    if (!session || !session->mSessionRes1) {
      return nullptr;
    }

    auto* const commandManager = static_cast<SessionCommandManagerRuntimeView*>(session->mSessionRes1);
    CommandDbMapStorageView& commandIssueMap = commandManager->commandIssueMap;

    CommandDbMapNodeView* const node = FindCommandNode(commandIssueMap, cmdId);
    if (!node || node == commandIssueMap.head) {
      return nullptr;
    }

    return reinterpret_cast<CommandIssueHelperRuntimeView*>(node->value);
  }

  constexpr std::uint32_t kCommandIssueUpdateEventTypeDecreaseCount = 2u;
  constexpr std::uint8_t kCommandIssueTreeBlack = 1u;
  constexpr std::uint32_t kCommandIssueQueueMaxCapacity = 53687091u;

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

  [[nodiscard]] CommandIssueUpdateEventRuntimeView* AllocateCommandIssueUpdateSlot()
  {
    auto* const storage = static_cast<CommandIssueUpdateEventRuntimeView*>(::operator new(sizeof(CommandIssueUpdateEventRuntimeView)));
    new (storage) CommandIssueUpdateEventRuntimeView{};
    InitializeCommandIssueUpdateEvent(*storage, 0, 0u);
    return storage;
  }

  void GrowCommandIssueUpdateQueue(CommandIssueUpdateQueueRuntimeView& queue)
  {
    const std::uint32_t oldCapacity = queue.capacity;
    if (oldCapacity == kCommandIssueQueueMaxCapacity) {
      throw std::bad_alloc();
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
    auto** const newSlots = static_cast<CommandIssueUpdateEventRuntimeView**>(
      ::operator new(sizeof(CommandIssueUpdateEventRuntimeView*) * static_cast<std::size_t>(newCapacity))
    );
    std::memset(newSlots, 0, sizeof(CommandIssueUpdateEventRuntimeView*) * static_cast<std::size_t>(newCapacity));

    if (queue.slots != nullptr && oldCapacity != 0u && queue.count != 0u) {
      for (std::uint32_t offset = 0u; offset < queue.count; ++offset) {
        std::uint32_t oldIndex = queue.readIndex + offset;
        if (oldIndex >= oldCapacity) {
          oldIndex -= oldCapacity;
        }

        std::uint32_t newIndex = queue.readIndex + offset;
        if (newIndex >= newCapacity) {
          newIndex -= newCapacity;
        }

        newSlots[newIndex] = queue.slots[oldIndex];
      }
    }

    ::operator delete(queue.slots);
    queue.slots = newSlots;
    queue.capacity = newCapacity;
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

  CUnitCommand* FindCommandById(CCommandDb* commandDb, const CmdId cmdId)
  {
    if (!commandDb || !commandDb->commands.header_ptr()) {
      return nullptr;
    }

    auto it = commandDb->commands.find(cmdId);
    if (it == commandDb->commands.end()) {
      return nullptr;
    }

    return &it->second;
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
   * Appends one command id into `CCommandDbRuntimeView::pendingReleasedCmdIds`,
   * growing vector storage when needed.
   */
  void AppendPendingReleasedCommandId(msvc8::vector<CmdId>& pendingReleasedCmdIds, const CmdId cmdId)
  {
    pendingReleasedCmdIds.push_back(cmdId);
  }

  /**
   * Address: 0x006E0EC0 (FUN_006E0EC0, sub_6E0EC0)
   *
   * IDA signature:
   * int __stdcall sub_6E0EC0(Moho::CCommandDB *commandDb, int cmdId);
   *
   * What it does:
   * Releases an unconsumed command id from the command DB:
   * removes the map entry when present, records recycled low-24 ids in the
   * rolling IdPool history slot, and queues the id into the pending-release vector
   * (matching `FUN_006E1A10` append semantics).
   */
  void ReleaseCommandIdIfUnconsumed(CCommandDb* commandDb, const CmdId cmdId)
  {
    if (!commandDb) {
      return;
    }

    if ((static_cast<std::uint32_t>(cmdId) & 0xFF000000u) == 0xFF000000u) {
      return;
    }

    auto* const runtime = reinterpret_cast<CCommandDbRuntimeView*>(commandDb);
    if (runtime->map.head != nullptr) {
      CommandDbMapNodeView* const node = FindCommandNode(*runtime, cmdId);
      if (node != nullptr && node != runtime->map.head) {
        EraseCommandNode(runtime->map, node);
      }
    }

    const std::uint32_t commandType = static_cast<std::uint32_t>(cmdId) & 0xFF000000u;
    if (commandType == 0x80000000u) {
      const std::int32_t retireIndex = (runtime->pool.mSubRes2.mEnd + 99) % 100;
      SimSubRes3& retireSlot = runtime->pool.mSubRes2.mData[retireIndex];
      AsBitSet(retireSlot).Add(static_cast<std::uint32_t>(cmdId) & 0x00FFFFFFu);
    }

    AppendPendingReleasedCommandId(runtime->pendingReleasedCmdIds, cmdId);
  }

  void InsertCommandNodeFixup(CommandDbMapStorageView& map, CommandDbMapNodeView* node)
  {
    CommandDbMapNodeView* const head = map.head;
    while (node->parent != head && node->parent->color == kTreeRed) {
      CommandDbMapNodeView* const grandParent = node->parent->parent;
      if (node->parent == grandParent->left) {
        CommandDbMapNodeView* uncle = grandParent->right;
        if (NodeColor(uncle, head) == kTreeRed) {
          node->parent->color = kTreeBlack;
          if (uncle != head) {
            uncle->color = kTreeBlack;
          }
          grandParent->color = kTreeRed;
          node = grandParent;
          continue;
        }

        if (node == node->parent->right) {
          node = node->parent;
          RotateLeft(map, node);
        }

        node->parent->color = kTreeBlack;
        grandParent->color = kTreeRed;
        RotateRight(map, grandParent);
      } else {
        CommandDbMapNodeView* uncle = grandParent->left;
        if (NodeColor(uncle, head) == kTreeRed) {
          node->parent->color = kTreeBlack;
          if (uncle != head) {
            uncle->color = kTreeBlack;
          }
          grandParent->color = kTreeRed;
          node = grandParent;
          continue;
        }

        if (node == node->parent->left) {
          node = node->parent;
          RotateRight(map, node);
        }

        node->parent->color = kTreeBlack;
        grandParent->color = kTreeRed;
        RotateLeft(map, grandParent);
      }
    }

    if (head->parent != nullptr && head->parent != head) {
      head->parent->color = kTreeBlack;
    }
    RefreshTreeBounds(map);
  }

  [[nodiscard]] CommandDbMapNodeView* AllocateCommandNode(const CmdId cmdId, CUnitCommand* const command)
  {
    auto* const node = static_cast<CommandDbMapNodeView*>(::operator new(sizeof(CommandDbMapNodeView)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->key = static_cast<std::uint32_t>(cmdId);
    node->value = command;
    node->color = kTreeRed;
    node->isNil = 0u;
    node->reserved16[0] = 0u;
    node->reserved16[1] = 0u;
    return node;
  }

  void InsertCommandNode(CommandDbMapStorageView& map, const CmdId cmdId, CUnitCommand* const command)
  {
    CommandDbMapNodeView* const head = map.head;
    if (head == nullptr) {
      return;
    }

    CommandDbMapNodeView* parent = head;
    CommandDbMapNodeView* cursor = head->parent;
    bool insertLeft = true;
    const std::uint32_t key = static_cast<std::uint32_t>(cmdId);

    while (cursor != nullptr && cursor != head && cursor->isNil == 0u) {
      parent = cursor;
      if (key < cursor->key) {
        insertLeft = true;
        cursor = cursor->left;
      } else {
        insertLeft = false;
        cursor = cursor->right;
      }
    }

    auto* const node = AllocateCommandNode(cmdId, command);
    node->left = head;
    node->right = head;
    node->parent = parent;

    if (parent == head) {
      head->parent = node;
      head->left = node;
      head->right = node;
    } else if (insertLeft) {
      parent->left = node;
      if (parent == head->left) {
        head->left = node;
      }
    } else {
      parent->right = node;
      if (parent == head->right) {
        head->right = node;
      }
    }

    ++map.size;
    InsertCommandNodeFixup(map, node);
  }

  [[nodiscard]] CUnitCommand* AddIssueDataToCommandDb(
    CCommandDb* const commandDb,
    const SSTICommandIssueData& issueData
  )
  {
    if (!commandDb) {
      return nullptr;
    }

    auto* const runtime = reinterpret_cast<CCommandDbRuntimeView*>(commandDb);
    CmdId commandId = issueData.nextCommandId;
    if ((static_cast<std::uint32_t>(commandId) & 0xFF000000u) == 0xFF000000u) {
      unsigned int nextLowId = 0u;
      if (runtime->pool.mReleasedLows.mWords.Empty()) {
        nextLowId = static_cast<unsigned int>(runtime->pool.mNextLowId);
        runtime->pool.mNextLowId = static_cast<std::int32_t>(nextLowId + 1u);
      } else {
        nextLowId = runtime->pool.mReleasedLows.GetNext(std::numeric_limits<unsigned int>::max());
        (void)runtime->pool.mReleasedLows.Remove(nextLowId);
      }

      commandId = static_cast<CmdId>(nextLowId | 0x80000000u);
    }

    CUnitCommand* const command = new (std::nothrow) CUnitCommand(runtime->sim, issueData, commandId);
    if (!command) {
      return nullptr;
    }

    InsertCommandNode(runtime->map, commandId, command);
    return command;
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

    boost::shared_ptr<Unit> ferryBeacon = currentCommand->mUnit.lock();
    return ferryBeacon ? ferryBeacon.get() : nullptr;
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
  [[maybe_unused]] void RetargetReverseLoadUnits(
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

  [[nodiscard]] CUnitCommand* IssueFactoryCommandToSelectedUnits(
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
  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnits(
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
  [[nodiscard]] RUnitBlueprint* ResolveUnitBlueprintFromLuaArgument(
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

  VTransform BuildUnitSpawnTransform(const SCoordsVec2& pos, const float heading)
  {
    const Wm3::Vec3f headingAxis{0.0f, 1.0f, 0.0f};
    const Wm3::Quatf orientation = Wm3::Quatf::FromAxisAngle(headingAxis, heading);
    const Wm3::Vec3f worldPosition{pos.x, 0.0f, pos.z};
    return VTransform(worldPosition, orientation);
  }

  /**
   * Address: 0x006FB420 (FUN_006FB420)
   *
   * IDA signature:
   * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, char const *);
   *
   * What it does:
   * Normalizes the prop blueprint id and resolves `RPropBlueprint` from game rules.
   */
  RPropBlueprint* ResolvePropBlueprintById(RRuleGameRules* rules, const char* blueprintId)
  {
    if (!rules || !blueprintId || !*blueprintId) {
      return nullptr;
    }

    // Binary chain:
    // - 0x0051E2E0 func_StringInitFilename
    // - 0x004A92A0 func_StringSetFilename
    std::string normalizedBlueprintId = blueprintId;
    gpg::STR_NormalizeFilenameLowerSlash(normalizedBlueprintId);

    const msvc8::string normalizedArg(normalizedBlueprintId.c_str());
    return rules->GetPropBlueprint(normalizedArg);
  }

  /**
   * Address: 0x006FB3B0 (FUN_006FB3B0)
   *
   * IDA signature:
   * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, Moho::RPropBlueprint const *);
   *
   * What it does:
   * Allocates `Prop` (0x288 bytes) and calls `Prop::Prop(sim, blueprint, trans)`.
   *
   * Recovery status:
   * Depends on `Entity::Entity` (0x00677C90) and `Prop::Prop` (0x006F9D90) source lift.
   */
  Prop* CreatePropFromBlueprintResolved(Sim* sim, const VTransform& transform, const RPropBlueprint* blueprint)
  {
    return Prop::CreateFromBlueprintResolved(sim, blueprint, transform);
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

    const RPropBlueprint* blueprint = ResolvePropBlueprintById(rules, blueprintId);
    (void)CreatePropFromBlueprintResolved(sim, spawnXform, blueprint);
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

  void SaveMapDataBestEffort(
    gpg::WriteArchive* archive, gpg::Rect2i* playableRect1, gpg::Rect2i* playableRect2, const gpg::RRef& ownerRef
  )
  {
    // 0x00745020 serializes map playable rectangles and cached tile rect list.
    // Current reconstruction keeps the two known Rect2 slots.
    SaveObjectByRType(archive, playableRect1, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
    SaveObjectByRType(archive, playableRect2, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
  }

  void LoadMapDataBestEffort(
    gpg::ReadArchive* archive, gpg::Rect2i* playableRect1, gpg::Rect2i* playableRect2, const gpg::RRef& ownerRef
  )
  {
    // 0x00745120 deserializes map playable rectangles and cached tile rect list.
    LoadObjectByRType(archive, playableRect1, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
    LoadObjectByRType(archive, playableRect2, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
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
        outMatches.push_back(overlayClass);
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

/**
 * Address: 0x00754C60 (FUN_00754C60, sub_754C60)
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
  LoadMapDataBestEffort(archive, &mPlayableRect1, &mPlayableRect2, ownerRef);
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
  LoadObjectByRType(archive, &mShields, {"std::list<Moho::Shield *>", "list<Moho::Shield *>"}, ownerRef);

  bool bitFlag = false;
  archive->ReadBool(&bitFlag);
  mCheatsEnabled = bitFlag;
  archive->ReadBool(&bitFlag);
  mGameOver = bitFlag;

  mCommandDB =
    static_cast<CCommandDb*>(LoadPointerByRType(archive, {"CCommandDB", "CCommandDb", "Moho::CCommandDB"}, ownerRef));
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
  SaveMapDataBestEffort(archive, &mPlayableRect1, &mPlayableRect2, ownerRef);
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

  archive->WriteBool(mCheatsEnabled);
  archive->WriteBool(mGameOver);
  SavePointerByRType(
    archive, mCommandDB, {"CCommandDB", "CCommandDb", "Moho::CCommandDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );
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
  mSyncFilter.CopyFrom(filter);

  delete outSyncData;
  outSyncData = new SSyncData{};
  outSyncData->mCurBeat = static_cast<int32_t>(mCurBeat);

  // +0x08FC latch: cleared by Sync after one beat is fully published.
  mDidProcess = false;
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
    it->second.RefreshBlipState();
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
    if (blueprintId) {
      mContext.Update(blueprintId, std::strlen(blueprintId) + 1u);
    } else {
      mContext.Update("<NULL>", 6u);
    }
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
 * Address: 0x00452070 (FUN_00452070, Moho::CDebugCanvas::DebugDrawLine)
 */
void CDebugCanvas::DebugDrawLine(const SDebugLine& line)
{
  lines.push_back(line);
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
    dest->w = 0.0f;
    dest->x = v1.x;
    dest->y = v1.y;
    dest->z = v1.z;
    return dest;
  }

  dest->w = (add.x * v1.x) + (add.y * v1.y) + (add.z * v1.z);
  dest->x = (add.z * v1.y) - (v1.z * add.y);
  dest->y = (v1.z * add.x) - (add.z * v1.x);
  dest->z = (add.y * v1.x) - (v1.y * add.x);
  return dest;
}

/**
 * Address: 0x0044F9B0 (FUN_0044F9B0, sub_44F9B0)
 *
 * What it does:
 * Thin wrapper around quaternion-vector rotation helper.
 */
Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat)
{
  if (!dest || !vec || !quat) {
    return dest;
  }

  Wm3::MultiplyQuaternionVector(dest, *vec, *quat);
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
 * Address: 0x00746820 (FUN_00746820, ?GetParticleBuffer@Sim@Moho@@QAEPAUSParticleBuffer@2@XZ)
 *
 * What it does:
 * Returns the shared particle buffer, allocating and binding it lazily on
 * first use.
 */
SParticleBuffer* Sim::GetParticleBuffer()
{
  if (!mParticleBuffer) {
    mParticleBuffer.reset(new SParticleBuffer());
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

  SDesyncInfo desync{};
  desync.hash1 = *expected;
  desync.hash2 = checksum;
  desync.beat = beat;
  desync.army = mCurCommandSource;
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

  if (!mCommandDB) {
    return true;
  }

  const auto* const runtimeCommandDb = reinterpret_cast<const CCommandDbRuntimeView*>(mCommandDB);
  if (!runtimeCommandDb->map.head) {
    return true;
  }

  const CommandDbMapNodeView* const existingNode = FindCommandNode(*runtimeCommandDb, cmdId);
  if (existingNode != nullptr && existingNode != runtimeCommandDb->map.head && existingNode->value != nullptr) {
    gpg::Warnf(
      "%s: ignoring issue of cmd id 0x%08x from %s because it is already in use.",
      callsite,
      cmdId,
      GetCurrentCommandSourceName()
    );
    return false;
  }

  return true;
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

  // The constructor body at 0x006A53F0 is still pending reconstruction.
  // Keep the cap-gate behavior exact, but avoid a partial/incorrect Unit object.
  Logf(
    "CreateUnit(params: bp=%s, army=%d): Unit constructor path (0x006A53F0) pending lift.\n",
    params.mBlueprint->mBlueprintId.raw_data_unsafe(),
    params.mArmy->ArmyId
  );
  return nullptr;
}

Unit* Sim::CreateUnitForScript(const SUnitConstructionParams& params, const bool doCallback)
{
  return CreateUnit(params, doCallback);
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

  SUnitConstructionParams params{};
  params.mArmy = army;
  params.mBlueprint = blueprint;
  params.mTransform = BuildUnitSpawnTransform(pos, heading);
  params.mUseLayerOverride = 0;
  params.mFixElevation = 0;
  params.mLayer = 0;
  params.mLinkSourceUnit = nullptr;
  params.mComplete = 1;

  (void)CreateUnit(params, true);
}

/**
 * Address: 0x00748C00 (FUN_00748C00)
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

  if (lua_pcall(state, 1, 0, 0) != 0) {
    const char* err = lua_tostring(state, -1);
    gpg::Warnf("Sim::ExecuteLuaInSim('%s') failed: %s", functionName, err ? err : "<unknown>");
  }

  lua_settop(state, oldTop);
}

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

  struct DumpUnitsCountEntry
  {
    const RUnitBlueprint* blueprint = nullptr;
    int count = 0;
  };

  std::vector<DumpUnitsCountEntry> counts;
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

  std::stable_sort(counts.begin(), counts.end(), [](const DumpUnitsCountEntry& lhs, const DumpUnitsCountEntry& rhs) {
    return lhs.count > rhs.count;
  });

  for (const DumpUnitsCountEntry& entry : counts) {
    if (entry.blueprint == nullptr) {
      continue;
    }

    gpg::Logf("%s %i", entry.blueprint->mBlueprintId.c_str(), entry.count);
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

  const float grantedEnergy = static_cast<float>(economyInfo->economy.mMaxStorage.ENERGY);
  const float grantedMass = static_cast<float>(economyInfo->economy.mMaxStorage.MASS);
  economyInfo->economy.mStored.ENERGY += grantedEnergy;
  economyInfo->economy.mStored.MASS += grantedMass;
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

  if (!sim || !sim->mEffectManager || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos) || !commandArgs) {
    return 0;
  }

  if (commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& blueprintName = commandArgs->at(1);
  sim->mEffectManager->CreateEmitter(*worldPos, blueprintName.c_str(), -1);
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

  if (!sim || !sim->mRules || !sim->mEffectManager || !commandArgs || !selectedUnits) {
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
      sim->mEffectManager->CreateAttachedEmitter(entity, boneIndex, emitterBlueprint.c_str(), -1);
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

  if (!sim || !sim->mEffectManager || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos)) {
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
  sim->mEffectManager->CreateLightParticle(*worldPos, texturePrimary, textureSecondary, size, lifetime, -1);
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

    // Binary 0x00749F40 still has an additional sync-filter packing pass here
    // (EntityDB lookup + serialization vector push helpers).
    for (auto* entity : mCoordEntities.owners_member<Entity, &Entity::mCoordNode>()) {
      AdvanceCoords(entity);
    }

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
      if (lua_isfunction(state, -1) && lua_pcall(state, 0, 1, 0) == 0) {
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
  struct LuaBlueprintTlsStateView
  {
    void* reserved00;                    // +0x00
    moho::RRuleGameRulesImpl* rules;     // +0x04
  };

  static_assert(
    offsetof(LuaBlueprintTlsStateView, rules) == 0x04,
    "LuaBlueprintTlsStateView::rules offset must be 0x04"
  );

  [[nodiscard]] LuaBlueprintTlsStateView* ResolveLuaBlueprintTlsState() noexcept
  {
#if defined(_M_IX86)
    void** const tlsPointerArray = reinterpret_cast<void**>(__readfsdword(0x2Cu));
    if (tlsPointerArray == nullptr) {
      return nullptr;
    }
    return static_cast<LuaBlueprintTlsStateView*>(tlsPointerArray[0]);
#else
    return nullptr;
#endif
  }

  [[nodiscard]] moho::RRuleGameRulesImpl* ResolveLuaBlueprintRules(LuaPlus::LuaState* const state) noexcept
  {
    LuaBlueprintTlsStateView* const tlsState = ResolveLuaBlueprintTlsState();
    if (tlsState != nullptr && tlsState->rules != nullptr) {
      return tlsState->rules;
    }
    return ResolveRulesImpl(state);
  }

  [[nodiscard]] moho::RUnitBlueprint*
  func_CreateRUnitBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);

  [[nodiscard]] moho::RPropBlueprint*
  func_CreateRPropBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);

  [[nodiscard]] moho::RProjectileBlueprint*
  func_CreateRProjectileBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);

  void func_RegisterBlueprint(moho::RBlueprint* blueprint, moho::RRuleGameRulesImpl* rules, const char* categoryName);

  int func_RegisterMeshBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);
  int func_RegisterTrailEmitterBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);
  int func_RegisterEmitterBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);
  int func_RegisterBeamBlueprint(LuaPlus::LuaState* state, moho::RRuleGameRulesBlueprintMap* destinationMap);

  /**
   * Address: 0x00528B90 (FUN_00528B90)
   *
   * What it does:
   * Fast-path helper that registers one unit blueprint from an already-cast
   * Lua state into the rules unit-blueprint map and category lookup.
   */
  int RegisterUnitBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    RUnitBlueprint* const blueprint = func_CreateRUnitBlueprint(state, &rules->mUnitBlueprints);
    func_RegisterBlueprint(reinterpret_cast<RBlueprint*>(blueprint), rules, "ALLUNITS");
    return 0;
  }

  /**
   * Address: 0x00528C60 (FUN_00528C60)
   *
   * What it does:
   * Fast-path helper that registers one prop blueprint from an already-cast
   * Lua state and updates category lookup lanes.
   */
  int RegisterPropBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    RPropBlueprint* const blueprint = func_CreateRPropBlueprint(state, &rules->mPropBlueprints);
    func_RegisterBlueprint(reinterpret_cast<RBlueprint*>(blueprint), rules, nullptr);
    return 0;
  }

  /**
   * Address: 0x00528D30 (FUN_00528D30)
   *
   * What it does:
   * Fast-path helper that registers one projectile blueprint from an already-cast
   * Lua state into the projectile map and category lookup.
   */
  int RegisterProjectileBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    RProjectileBlueprint* const blueprint = func_CreateRProjectileBlueprint(state, &rules->mProjectileBlueprints);
    func_RegisterBlueprint(reinterpret_cast<RBlueprint*>(blueprint), rules, "ALLPROJECTILES");
    return 0;
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
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
  (void)func_RegisterMeshBlueprint(state, &rules->mMeshBlueprints);
  return 0;
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
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
  return func_RegisterTrailEmitterBlueprint(state, &rules->mTrailBlueprints);
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
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
  return func_RegisterEmitterBlueprint(state, &rules->mEmitterBlueprints);
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
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
  return func_RegisterBeamBlueprint(state, &rules->mBeamBlueprints);
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
    SimLuaInitSet(),
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
int moho::cfunc_BlueprintLoaderUpdateProgress(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);

#if defined(_M_IX86)
  struct LoaderTlsStateView
  {
    void* reserved00;                             // +0x00
    void* reserved04;                             // +0x04
    moho::CBackgroundTaskControl* loadControl;   // +0x08
  };
  static_assert(
    offsetof(LoaderTlsStateView, loadControl) == 0x08,
    "LoaderTlsStateView::loadControl offset must be 0x08"
  );

  void** const tlsPointerArray = reinterpret_cast<void**>(__readfsdword(0x2Cu));
  if (tlsPointerArray != nullptr) {
    const auto* const tlsState = static_cast<const LoaderTlsStateView*>(tlsPointerArray[0]);
    if (tlsState != nullptr && tlsState->loadControl != nullptr && tlsState->loadControl->mHandle != nullptr) {
      tlsState->loadControl->mHandle->UpdateLoadingProgress();
    }
  }
#endif

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

  const CategoryWordRangeView parsedCategory = rules->ParseEntityCategory(categoryText);

  EntityCategorySet category{};
  category.mBitsHeader = reinterpret_cast<BVSetBitsHeader*>(static_cast<std::uintptr_t>(parsedCategory.mWordUniverseHandle));
  category.mFlags = parsedCategory.mReserved04;
  category.mBits = CategoryWordRangeAsBVIntSet(parsedCategory);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &category);
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

  const CategoryWordRangeView parsedCategory = rules->ParseEntityCategory(categoryText);

  EntityCategorySet category{};
  category.mBitsHeader = reinterpret_cast<BVSetBitsHeader*>(static_cast<std::uintptr_t>(parsedCategory.mWordUniverseHandle));
  category.mFlags = parsedCategory.mReserved04;
  category.mBits = CategoryWordRangeAsBVIntSet(parsedCategory);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &category);
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

  EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
  if (commandCap > RULEUCC_Tactical) {
    if (commandCap > RULEUCC_Pause) {
      if (commandCap > RULEUCC_Reclaim) {
        if (commandCap == RULEUCC_SpecialAction) {
          commandType = EUnitCommandType::UNITCOMMAND_SpecialAction;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_Reclaim:
          commandType = EUnitCommandType::UNITCOMMAND_Reclaim;
          break;
        case RULEUCC_Overcharge:
          commandType = EUnitCommandType::UNITCOMMAND_OverCharge;
          break;
        case RULEUCC_Dive:
          commandType = EUnitCommandType::UNITCOMMAND_Dive;
          break;
        default:
          commandType = EUnitCommandType::UNITCOMMAND_None;
          break;
        }
      }
    } else {
      if (commandCap == RULEUCC_Pause) {
        commandType = EUnitCommandType::UNITCOMMAND_Pause;
      } else if (commandCap > RULEUCC_SiloBuildTactical) {
        if (commandCap == RULEUCC_SiloBuildNuke) {
          commandType = EUnitCommandType::UNITCOMMAND_BuildSiloNuke;
        } else if (commandCap == RULEUCC_Sacrifice) {
          commandType = EUnitCommandType::UNITCOMMAND_Sacrifice;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_SiloBuildTactical:
          commandType = EUnitCommandType::UNITCOMMAND_BuildSiloTactical;
          break;
        case RULEUCC_Teleport:
          commandType = EUnitCommandType::UNITCOMMAND_Teleport;
          break;
        case RULEUCC_Ferry:
          commandType = EUnitCommandType::UNITCOMMAND_Ferry;
          break;
        default:
          commandType = EUnitCommandType::UNITCOMMAND_None;
          break;
        }
      }
    }
  } else if (commandCap == RULEUCC_Tactical) {
    commandType = EUnitCommandType::UNITCOMMAND_Tactical;
  } else if (commandCap > RULEUCC_Repair) {
    if (commandCap > RULEUCC_CallTransport) {
      if (commandCap == RULEUCC_Nuke) {
        commandType = EUnitCommandType::UNITCOMMAND_Nuke;
      }
    } else {
      switch (commandCap) {
      case RULEUCC_CallTransport:
        commandType = EUnitCommandType::UNITCOMMAND_TransportLoadUnits;
        break;
      case RULEUCC_Capture:
        commandType = EUnitCommandType::UNITCOMMAND_Capture;
        break;
      case RULEUCC_Transport:
        commandType = EUnitCommandType::UNITCOMMAND_TransportUnloadUnits;
        break;
      default:
        commandType = EUnitCommandType::UNITCOMMAND_None;
        break;
      }
    }
  } else if (commandCap == RULEUCC_Repair) {
    commandType = EUnitCommandType::UNITCOMMAND_Repair;
  } else {
    switch (commandCap) {
    case RULEUCC_Move:
      commandType = EUnitCommandType::UNITCOMMAND_Move;
      break;
    case RULEUCC_Stop:
      commandType = EUnitCommandType::UNITCOMMAND_Stop;
      break;
    case RULEUCC_Attack:
      commandType = EUnitCommandType::UNITCOMMAND_Attack;
      break;
    case RULEUCC_Guard:
      commandType = EUnitCommandType::UNITCOMMAND_Guard;
      break;
    case RULEUCC_Patrol:
      commandType = EUnitCommandType::UNITCOMMAND_Patrol;
      break;
    default:
      commandType = EUnitCommandType::UNITCOMMAND_None;
      break;
    }
  }

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

  CWldSession* const session = WLD_GetActiveSession();
  if (session != nullptr && (session->IsReplay || session->GetFocusUserArmy() != nullptr || !session->IsMultiplayer)) {
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
    UserEntity* const userEntity = reinterpret_cast<UserEntity*>(userUnit);
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
    UserEntity* const userEntity = reinterpret_cast<UserEntity*>(userUnit);
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

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->mVarDat.mNeutrals.Contains(secondArmy->mArmyIndex);
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
  static CScrLuaBinder binder(
    SimLuaInitSet(),
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
    SimLuaInitSet(),
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

  const UserEntityWeakSetRuntimeView* const idleSet = ResolveIdleUnitSetView(focusArmy, false);
  if (idleSet == nullptr || idleSet->head == nullptr || idleSet->size == 0u) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<int>(idleSet->size), 0u);

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

  const UserEntityWeakSetRuntimeView* const idleSet = ResolveIdleUnitSetView(focusArmy, true);
  if (idleSet == nullptr || idleSet->head == nullptr || idleSet->size == 0u) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<int>(idleSet->size), 0u);

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
    SimLuaInitSet(),
    "GetSelectedUnits",
    &moho::cfunc_GetSelectedUnits,
    nullptr,
    "<global>",
    kGetSelectedUnitsHelpText
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

      UserEntity* const userEntity = reinterpret_cast<UserEntity*>(userUnit);
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
      UserEntity* const userEntity = reinterpret_cast<UserEntity*>(userUnit);
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
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
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
    SimLuaInitSet(),
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

  session->mScenarioInfo.PushStack(state);
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
    SimLuaInitSet(),
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

  const msvc8::vector<UserArmy*>& armies = session->userArmies;
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
    activeDriver->DecreaseCommandCount(commandIssue->commandId, 1);
    QueueCommandIssueDecreaseCountEvent(*commandIssue, commandId, 1);
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
  std::map<std::string, std::vector<std::string>> filesByProfile{};
  USER_GetSpecialFiles(specialFileType, directory, extension, filesByProfile);

  LuaPlus::LuaObject filesTable(state);
  filesTable.AssignNewTable(state, 0, 0);

  for (const auto& [profileName, profileFiles] : filesByProfile) {
    LuaPlus::LuaObject profileTable(state);
    profileTable.AssignNewTable(state, 0, 0);

    std::int32_t fileIndex = 1;
    for (const std::string& fileNameWithExtension : profileFiles) {
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
  PatchMiddleMouseScrubOpcode(invertMiddleMouse);
  return 0;
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

  gpg::Rect2f queryRect{};
  if (!ParseRectFromLuaArguments(state, kGetUnitsInRectHelpText, queryRect)) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  Sim* const sim = ResolveGlobalSim(rawState);
  CEntityDb* const entityDb = sim ? sim->mEntityDB : nullptr;
  if (entityDb == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  std::vector<Unit*> unitsInRect{};
  for (Entity* const entity : entityDb->Entities()) {
    if (entity == nullptr || !IsEntityPositionInsideRect(entity, queryRect)) {
      continue;
    }

    Unit* const unit = entity->IsUnit();
    if (unit != nullptr) {
      unitsInRect.push_back(unit);
    }
  }

  if (unitsInRect.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable{};
  resultTable.AssignNewTable(state, static_cast<int>(unitsInRect.size()), 0);
  int luaIndex = 1;
  for (Unit* const unit : unitsInRect) {
    const LuaPlus::LuaObject unitObject = unit->GetLuaObject();
    resultTable.SetObject(luaIndex, unitObject);
    ++luaIndex;
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

  gpg::Rect2f queryRect{};
  if (!ParseRectFromLuaArguments(state, kGetReclaimablesInRectHelpText, queryRect)) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  Sim* const sim = ResolveGlobalSim(rawState);
  CEntityDb* const entityDb = sim ? sim->mEntityDB : nullptr;
  if (entityDb == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  std::vector<Entity*> reclaimablesInRect{};
  for (Entity* const entity : entityDb->Entities()) {
    if (entity == nullptr || !IsEntityPositionInsideRect(entity, queryRect)) {
      continue;
    }

    if (entity->IsUnit() == nullptr && entity->IsProp() == nullptr) {
      continue;
    }

    reclaimablesInRect.push_back(entity);
  }

  if (reclaimablesInRect.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable{};
  resultTable.AssignNewTable(state, static_cast<int>(reclaimablesInRect.size()), 0);
  int luaIndex = 1;
  for (Entity* const entity : reclaimablesInRect) {
    const LuaPlus::LuaObject entityObject = entity->mLuaObj;
    resultTable.SetObject(luaIndex, entityObject);
    ++luaIndex;
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

  TerrainTypeGrid& terrainTypeGrid = map->mTerrainType;
  const std::int32_t minX = std::max(rect.x0, 0);
  const std::int32_t minZ = std::max(rect.z0, 0);
  const std::int32_t maxX = std::min(rect.x1, terrainTypeGrid.width);
  const std::int32_t maxZ = std::min(rect.z1, terrainTypeGrid.height);

  if (maxX <= minX || maxZ <= minZ) {
    return 0;
  }

  for (std::int32_t z = minZ; z < maxZ; ++z) {
    std::uint8_t* const row =
      &terrainTypeGrid.data[static_cast<std::size_t>(z) * static_cast<std::size_t>(terrainTypeGrid.width)];
    for (std::int32_t x = minX; x < maxX; ++x) {
      row[x] = terrainType;
    }
  }

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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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
  const RPropBlueprint* const blueprint = ResolvePropBlueprintById(sim ? sim->mRules : nullptr, blueprintId);
  Prop* const prop = CreatePropFromBlueprintResolved(sim, transform, blueprint);
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
  const RPropBlueprint* const blueprint = ResolvePropBlueprintById(sim ? sim->mRules : nullptr, blueprintId);
  Prop* const prop = CreatePropFromBlueprintResolved(sim, entityBoneTransform, blueprint);
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
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
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

  int depositTypeIndex = 0;
  const std::string_view typeView = depositTypeName.view();
  if (typeView == "Mass") {
    depositTypeIndex = 1;
  } else if (typeView == "Hydrocarbon") {
    depositTypeIndex = 2;
  }

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

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->Neutrals.Contains(static_cast<std::uint32_t>(secondArmy->ArmyId));
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

/**
 * Address: 0x0074CFB0 (FUN_0074CFB0, sub_74CFB0)
 */
void SimSerializer::RegisterSerializeFunctions()
{
  // 0x0074CF80 / 0x00744F90 initialize these callback slots in static init.
  if (mSerLoadFunc == nullptr) {
    mSerLoadFunc = &SimSerializerLoadThunk;
  }
  if (mSerSaveFunc == nullptr) {
    mSerSaveFunc = &SimSerializerSaveThunk;
  }

  gpg::RType* type = gpg::LookupRType(typeid(Sim));
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
