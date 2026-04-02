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
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <utility>
#include <vector>

#include <Windows.h>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/command/CCommandDb.h"
#include "moho/console/CVarAccess.h"
#include "moho/debug/RDebugOverlayClass.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/path/PathTables.h"
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
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/resource/RResId.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/UserArmy.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"

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
  constexpr const char* kEntityCreatePropAtBoneHelpText = "Entity:CreatePropAtBone(boneindex,prop_blueprint_id)";
  constexpr const char* kCreateResourceDepositHelpText = "type, x, y, z, size";
  constexpr const char* kSimCallbackHelpText =
    "SimCallback(callback[,bool]): Execute a lua function in sim\n"
    "callback = {\n"
    "   Func    =   function name (in the SimCallbacks.lua module) to call\n"
    "   Args    =   Arguments as a lua object\n"
    "}\n"
    "If bool is specified and true, sends the current selection with the command\n";
  constexpr const char* kGetSelectedUnitsHelpText = "table GetSelectedUnits() - return a table of the currently selected units";
  constexpr const char* kUnknownResourceDepositTypeMessage = "unknown resource deposit type: %s";
  constexpr const char* kGetEconomyTotalsHelpText = "table GetEconomyTotals()";
  constexpr const char* kGetEconomyTotalsMissingSessionWarning =
    "Attempt to call GetEconomyTotals before world sessions exists.";
  constexpr const char* kCallbackPacketMessage = "Callback packet received, exit sync is over";
  constexpr const char* kDiscardedPointerMessage = "Discarded: %p";
  constexpr const char* kRecvPointerMessage = "recv Ptr: %p";
  constexpr const char* kSetInvertMidMouseButtonHelpText = "SetInvertMidMouseButton";
  constexpr const char* kSetArmyColorHelpText = "SetArmyColor(army,r,g,b)";
  constexpr const char* kSetTerrainTypeHelpText = "SetTerrainType( x, z, terrainTypeTable )";
  constexpr const char* kSetTerrainTypeRectHelpText = "SetTerrainTypeRect( rect, terrainTypeTable )";
  constexpr const char* kSetPlayableRectHelpText = "SetPlayableRect( minX, minZ, maxX, maxZ )";
  constexpr const char* kSetAutoModeHelpText = "See if anyone in the list is auto building";
  constexpr const char* kSetAutoSurfaceModeHelpText = "See if anyone in the list is auto surfacing";
  constexpr const char* kSpecFootprintsHelpText = "SpecFootprints { spec } -- define the footprint types for pathfinding";
  constexpr const char* kFormatTimeHelpText =
    "string FormatTime(seconds) - format a string displaying the time specified in seconds";
  constexpr const char* kGetGameTimeHelpText = "GetGameTime()";
  constexpr const char* kSetOverlayFiltersHelpText = "SetOverlayFilters(list)";
  constexpr const char* kNoSessionStartedText = "No session started.";
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
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaInvalidBoolWarning = "%s\n  invalid argument %d, use as boolean";
  constexpr const char* kKernel32ModuleName = "kernel32.dll";
  constexpr const char* kVirtualProtectExportName = "VirtualProtect";
  constexpr std::size_t kDiscardClientSlotCount = 17u;
  constexpr SIZE_T kInvertMidMousePatchSize = 0x9u;
  constexpr std::uintptr_t kLuaCallbackDispatchBlockedFlagEa = 0x011FD23Fu;
  constexpr std::uintptr_t kInvertMidMouseOpcodeXEa = 0x0086E01Fu;
  constexpr std::uintptr_t kInvertMidMouseOpcodeYEa = 0x0086E027u;

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

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] Sim* ResolveGlobalSim(lua_State* const luaContext) noexcept
  {
    if (!luaContext || !luaContext->l_G) {
      return nullptr;
    }
    return luaContext->l_G->globalUserData;
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
    static CScrLuaInitFormSet sSet("sim");
    return sSet;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    static CScrLuaInitFormSet sSet("user");
    return sSet;
  }

  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const unit) noexcept
  {
    return unit ? reinterpret_cast<IUnit*>(unit->mIUnitAndScriptBridge) : nullptr;
  }

  [[nodiscard]] const IUnit* ResolveIUnitBridge(const UserUnit* const unit) noexcept
  {
    return unit ? reinterpret_cast<const IUnit*>(unit->mIUnitAndScriptBridge) : nullptr;
  }

  [[nodiscard]] LuaPlus::LuaObject GetLuaTableFieldByName(
    const LuaPlus::LuaObject& tableObject,
    const char* const fieldName
  )
  {
    LuaPlus::LuaObject out;

    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const rawState = state->GetCState();
    if (!rawState) {
      return out;
    }

    const int top = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(rawState);
    lua_pushstring(rawState, fieldName ? fieldName : "");
    lua_gettable(rawState, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(rawState, top);
    return out;
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
      payload = GetLuaTableFieldByName(payload, "_c_object");
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

  bool ParseIntLiteral(const char* text, int& outValue)
  {
    if (!text) {
      return false;
    }

    char* endPtr = nullptr;
    const long parsed = std::strtol(text, &endPtr, 10);
    if (endPtr == text || (endPtr && *endPtr != '\0')) {
      return false;
    }
    if (parsed < static_cast<long>(std::numeric_limits<int>::min()) ||
        parsed > static_cast<long>(std::numeric_limits<int>::max())) {
      return false;
    }

    outValue = static_cast<int>(parsed);
    return true;
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
   * Returns the exact command-id node in the command DB map, or the head/sentinel when absent.
   */
  [[nodiscard]] const CommandDbMapNodeView* FindCommandNode(const CCommandDbRuntimeView& commandDb, const CmdId cmdId)
  {
    CommandDbMapNodeView* const head = commandDb.map.head;
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

  [[nodiscard]] CommandDbMapNodeView* FindCommandNode(CCommandDbRuntimeView& commandDb, const CmdId cmdId)
  {
    return const_cast<CommandDbMapNodeView*>(
      FindCommandNode(static_cast<const CCommandDbRuntimeView&>(commandDb), cmdId)
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

    return &it->second;
  }

  Entity* FindEntityById(CEntityDb* entityDb, const EntId id)
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      Entity* entity = *it;
      if (entity && entity->id_ == id) {
        return entity;
      }
    }

    return nullptr;
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

    runtime->pendingReleasedCmdIds.push_back(cmdId);
  }

  // 0x00748AA0 resolves unit blueprints from RResId via RRuleGameRules::GetUnitBlueprint.
  const RUnitBlueprint* ResolveUnitBlueprint(RRuleGameRules* rules, const RResId& blueprintId)
  {
    if (!rules) {
      return nullptr;
    }

    return rules->GetUnitBlueprint(blueprintId);
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
    if (overlayType.newRefFunc_ == nullptr) {
      return nullptr;
    }

    const gpg::RRef overlayRef = overlayType.newRefFunc_();
    return static_cast<RDebugOverlay*>(overlayRef.mObj);
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

  mDesyncLogLine = gpg::STR_Printf("%sbeat%05d.log", mLogFilePrefix.c_str(), static_cast<int>(mCurBeat));
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

// 0x00746280
std::FILE* Sim::Logf(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  if (mLog) {
    vfprintf(mLog, fmt, args);
  }

  va_end(args);
  return mLog;
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
 * Address: 0x00746720 (FUN_00746720, ?GetDebugCanvas@Sim@Moho@@QAEPAVCDebugCanvas@2@XZ)
 */
CDebugCanvas* Sim::GetDebugCanvas()
{
  if (!mDebugCanvas1) {
    mDebugCanvas1.reset(new CDebugCanvas());
  }
  return mDebugCanvas1.get();
}

// 0x007466F0
const char* Sim::GetCurrentCommandSourceName() const
{
  if (mCurCommandSource == kInvalidCommandSource ||
      static_cast<std::size_t>(mCurCommandSource) >= mCommandSources.size()) {
    return "???";
  }

  return mCommandSources[mCurCommandSource].mName.c_str();
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

// 0x00747320
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

// 0x00747360
bool Sim::OkayToMessWith(Entity* entity)
{
  return OkayToMessWith(entity ? static_cast<SimArmy*>(entity->ArmyRef) : nullptr);
}

// 0x007473B0
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

// 0x00748650
void Sim::SetCommandSource(const CommandSourceId sourceId)
{
  if (sourceId == kInvalidCommandSource || sourceId < static_cast<CommandSourceId>(mCommandSources.size())) {
    mCurCommandSource = static_cast<int32_t>(sourceId);
    return;
  }

  gpg::Warnf("Sim::SetCommandSource(%d): invalid source -- ignoring following commands.", sourceId);
  mCurCommandSource = static_cast<int32_t>(kInvalidCommandSource);
}

// 0x007486B0
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

// 0x007487C0
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
}

// 0x00748960
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

// 0x007489A0
void Sim::Resume()
{
  if (mCurCommandSource != kInvalidCommandSource) {
    mPausedByCommandSource = -1;
  }
}

// 0x007489C0
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

// 0x00748CD0
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

// 0x00748D50
void Sim::ProcessInfoPair(void* id, const char* key, const char* val)
{
  const EntId entityId = static_cast<EntId>(reinterpret_cast<std::uintptr_t>(id));
  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity)) {
    return;
  }

  Unit* unit = entity->IsUnit();
  if (!unit || unit->IsDead()) {
    return;
  }

  bool boolValue = false;

  if (gpg::STR_EqualsNoCase(key, "SetAutoMode")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetAutoMode(boolValue);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoSurfaceMode")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetAutoSurfaceMode(boolValue);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "CustomName")) {
    unit->SetCustomName(std::string(val ? val : ""));
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildTactical")) {
    if (gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 0);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildNuke")) {
    if (gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 1);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetRepeatQueue")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetRepeatQueue(boolValue);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetPaused")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetPaused(boolValue);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetFireState")) {
    int fireState = 0;
    if (ParseIntLiteral(val, fireState) && fireState >= 0 && fireState <= 2) {
      unit->SetFireState(fireState);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "ToggleScriptBit")) {
    int bitIndex = 0;
    if (ParseIntLiteral(val, bitIndex)) {
      unit->ToggleScriptBit(bitIndex);
    }
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayNoStagingPlatformsVO")) {
    static_cast<CScriptObject*>(unit)->CallbackStr("OnPlayNoStagingPlatformsVO");
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayBusyStagingPlatformsVO")) {
    static_cast<CScriptObject*>(unit)->CallbackStr("OnPlayBusyStagingPlatformsVO");
    return;
  }

  Logf(
    "ProcessInfoPair(entity=%d, key=%s, val=%s): key path not yet lifted.\n",
    entityId,
    key ? key : "<null>",
    val ? val : "<null>"
  );
}

/**
 * Address: 0x00749290 (FUN_00749290)
 *
 * What it does:
 * Validates command-id ownership, collects selected units, and (for now) keeps
 * id lifecycle consistent while full dispatch recovery remains in progress.
 */
void Sim::IssueCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueCommand")) {
    return;
  }

  std::vector<Unit*> selectedUnits;
  selectedUnits.reserve(entities.Bits().Count());

  auto collectUnit = [this, &selectedUnits](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    if (std::find(selectedUnits.begin(), selectedUnits.end(), unit) == selectedUnits.end()) {
      selectedUnits.push_back(unit);
    }
  };

  entities.ForEachValue([&collectUnit](const unsigned int value) {
    collectUnit(static_cast<EntId>(value));
  });

  if (selectedUnits.empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  // 0x00749290 gates command type 31 behind CheatsEnabled().
  const int commandType = static_cast<int>(commandIssueData.mCommandType);
  if (commandType == 31 && !CheatsEnabled()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  // Full UNIT_IssueCommand dispatch (0x006F12C0) still depends on local
  // helper containers built by 0x0057DDD0 / 0x005796A0.
  Logf(
    "IssueCommand(cmd=0x%08x, units=%zu, clear=%d, type=%d): dispatch path pending lift.\n",
    commandIssueData.nextCommandId,
    selectedUnits.size(),
    clearQueue ? 1 : 0,
    commandType
  );
  ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
}

/**
 * Address: 0x007494B0 (FUN_007494B0)
 *
 * What it does:
 * Validates command-id ownership, collects selected factory units, and preserves
 * command-id recycling while factory dispatch lift is still pending.
 */
void Sim::IssueFactoryCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueFactoryCommand")) {
    return;
  }

  std::vector<Unit*> selectedFactories;
  selectedFactories.reserve(entities.Bits().Count());

  auto collectFactory = [this, &selectedFactories](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    if (std::find(selectedFactories.begin(), selectedFactories.end(), unit) == selectedFactories.end()) {
      selectedFactories.push_back(unit);
    }
  };

  entities.ForEachValue([&collectFactory](const unsigned int value) {
    collectFactory(static_cast<EntId>(value));
  });

  if (selectedFactories.empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  // Full dispatch path calls 0x006F14D0 after helper-list setup.
  Logf(
    "IssueFactoryCommand(cmd=0x%08x, factories=%zu, clear=%d): dispatch path pending lift.\n",
    commandIssueData.nextCommandId,
    selectedFactories.size(),
    clearQueue ? 1 : 0
  );
  ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
}

// 0x00749680
void Sim::IncreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->IncreaseCount(count);
  }
}

// 0x007496E0
void Sim::DecreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->DecreaseCount(count);
  }
}

// 0x00749740
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

// 0x00749800
void Sim::SetCommandType(const CmdId cmdId, const EUnitCommandType commandType)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mCmdType = commandType;
  command->mNeedsUpdate = true;
}

// 0x00749860
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

// 0x00749970
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

// 0x00749B60
void Sim::LuaSimCallback(
  const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  if (!callbackName || !mLuaState || !mLuaState->m_state) {
    return;
  }

  lua_State* state = mLuaState->m_state;
  const int oldTop = lua_gettop(state);

  lua_getglobal(state, "DoCallback");
  if (!lua_isfunction(state, -1)) {
    lua_settop(state, oldTop);
    return;
  }

  lua_pushstring(state, callbackName);

  try {
    LuaPlus::LuaPush(state, args);
  } catch (const std::exception&) {
    lua_pushnil(state);
  }

  lua_newtable(state);
  int luaIndex = 1;

  auto appendUnitLuaObject = [this, state, &luaIndex](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    LuaPlus::LuaObject unitObject = unit->GetLuaObject();
    lua_pushnumber(state, static_cast<lua_Number>(luaIndex++));
    LuaPlus::LuaPush(state, unitObject);
    lua_settable(state, -3);
  };

  entities.ForEachValue([&appendUnitLuaObject](const unsigned int value) {
    appendUnitLuaObject(static_cast<EntId>(value));
  });

  if (lua_pcall(state, 3, 0, 0) != 0) {
    const char* err = lua_tostring(state, -1);
    gpg::Warnf("Sim::LuaSimCallback('%s') failed: %s", callbackName, err ? err : "<unknown>");
  }

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
  sim->mEffectManager->CreateLightParticle(*worldPos, texturePrimary, textureSecondary, lifetime, size, -1);
  return 0;
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

// 0x0074B100
void Sim::EndGame()
{
  mGameEnded = true;
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
  return cfunc_SpecFootprintsL(ResolveBindingState(luaContext));
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
  return cfunc_EntityCategoryContainsSimL(ResolveBindingState(luaContext));
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
  return cfunc_EntityCategoryCountL(ResolveBindingState(luaContext));
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
  return cfunc_EntityCategoryContainsUserL(ResolveBindingState(luaContext));
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
  return cfunc_EntityCategoryFilterDownUserL(ResolveBindingState(luaContext));
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
  return cfunc_EntityCategoryFilterOutL(ResolveBindingState(luaContext));
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
  return cfunc_SimCallbackL(ResolveBindingState(luaContext));
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
  return cfunc_SetAutoModeL(ResolveBindingState(luaContext));
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
  return cfunc_SetAutoSurfaceModeL(ResolveBindingState(luaContext));
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
  return cfunc_GetSelectedUnitsL(ResolveBindingState(luaContext));
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
  return cfunc_GetEconomyTotalsL(ResolveBindingState(luaContext));
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
  return cfunc_FormatTimeL(ResolveBindingState(luaContext));
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
  return cfunc_EndGameL(ResolveBindingState(luaContext));
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
  return cfunc_IsGameOverL(ResolveBindingState(luaContext));
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
  return cfunc_SetPlayableRectL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x006FC590 (FUN_006FC590, cfunc_EntityCreatePropAtBone)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_EntityCreatePropAtBoneL`.
 */
int moho::cfunc_EntityCreatePropAtBone(lua_State* const luaContext)
{
  return cfunc_EntityCreatePropAtBoneL(ResolveBindingState(luaContext));
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
  return cfunc_CreateResourceDepositL(ResolveBindingState(luaContext));
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
 * Address: 0x00707D60 (FUN_00707D60, ?ARMY_FromLuaState@Moho@@YAPAVSimArmy@1@PAVLuaState@LuaPlus@@VLuaObject@4@@Z)
 *
 * What it does:
 * Resolves a Lua army selector (number or name) into `CArmyImpl*`.
 */
CArmyImpl* moho::ARMY_FromLuaState(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& armyObject)
{
  Sim* const sim = (state && state->m_state) ? ResolveGlobalSim(state->m_state) : nullptr;
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
  Sim* const sim = (state && state->m_state) ? ResolveGlobalSim(state->m_state) : nullptr;
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
  return cfunc_SetArmyColorL(ResolveBindingState(luaContext));
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
