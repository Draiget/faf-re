// Engine addition (dedicated-server plan WPL.4, WPR.11): the reflection editor
// window (WRefEditDialog, a wxDialog over one reflected object) and the
// SC_CreateEntityDialog console command that opens it on the selected unit's
// blueprint, moved unchanged out of Sim.cpp: both are user-side wx code, and
// the simulation's objects carry no wx.

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"
#include "platform/WxWidgets.h"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/sizer.h>
#include <wx/treectrl.h>
#include <wx/treelistctrl.h>

using namespace moho;

namespace
{
  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const unit) noexcept
  {
    return unit ? static_cast<IUnit*>(unit) : nullptr;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004A47C0 (FUN_004A47C0, ?REF_CreateEditDialog@Moho@@YAXPAVwxWindow@@ABVRRef@gpg@@PBD_N@Z)
   *
   * What it does:
   * Opens a modeless reflection editor on `ref`, titled `name`. Nothing reads
   * the parent or the flag: the dialog is always top-level, and the shipped
   * code has both dropped at the one call site.
   */
  void REF_CreateEditDialog(wxWindow* parent, const gpg::RRef& ref, const char* name, bool);

  /**
   * VFTABLE: 0x00E06F18 (??_7CRefTreeItemData@Moho@@6B@)
   *
   * One row of the reflection editor: the value it shows, whether its value
   * may be edited, its label, and whether its children have been listed.
   * The deleting destructor (0x004A3D30) is the compiler's.
   */
  class CRefTreeItemData : public wxTreeItemData
  {
  public:
    /**
     * Address: 0x004A3CB0 (FUN_004A3CB0)
     *
     * What it does:
     * Copies the row's reference, edit flag and label; its children are not
     * listed yet.
     */
    CRefTreeItemData(const gpg::RRef& ref, bool editable, const msvc8::string& name);

    gpg::RRef mRef;      // +0x08
    bool mEditable;      // +0x10
    msvc8::string mName; // +0x14
    bool mPopulated;     // +0x30
  };

  static_assert(offsetof(CRefTreeItemData, mRef) == 0x08, "CRefTreeItemData::mRef offset must be 0x08");
  static_assert(offsetof(CRefTreeItemData, mEditable) == 0x10, "CRefTreeItemData::mEditable offset must be 0x10");
  static_assert(offsetof(CRefTreeItemData, mName) == 0x14, "CRefTreeItemData::mName offset must be 0x14");
  static_assert(offsetof(CRefTreeItemData, mPopulated) == 0x30, "CRefTreeItemData::mPopulated offset must be 0x30");
  static_assert(sizeof(CRefTreeItemData) == 0x34, "CRefTreeItemData size must be 0x34");

  /**
   * VFTABLE: 0x00E06F24 (??_7WRefEditDialog@Moho@@6B@)
   *
   * A modeless window over one reflected object: a tree of its fields and
   * elements with their values and field descriptions. Rows list their
   * children the first time they are expanded, and a writable field's value
   * is edited in place (the Value column, through FA's column edit in its
   * wxTreeListCtrl).
   *
   * Slot 0 is wxDialog::GetClassInfo (0x004A3970); 47, 139 and 140 are inline
   * wx copies. The destructor (0x004A4100, deleting 0x004A40E0) is the
   * compiler's.
   */
  class WRefEditDialog : public wxDialog
  {
  public:
    /**
     * Address: 0x004A3DB0 (FUN_004A3DB0, ??0WRefEditDialog@Moho@@QAE@@Z)
     *
     * What it does:
     * A resizable 640x480 dialog titled `name`, filled by a Property/Value/
     * Description tree list whose hidden root is `ref`.
     */
    WRefEditDialog(const gpg::RRef& ref, const char* name);

    /**
     * Address: 0x004A4110 (FUN_004A4110)
     *
     * What it does:
     * Adds a row for `ref` labelled `name` under `parent`, or as the root when
     * `parent` is not set. The row gets an expand button when the value has
     * fields or elements.
     */
    wxTreeItemId AddItem(const wxTreeItemId& parent, const msvc8::string& name, const gpg::RRef& ref, bool editable);

    /**
     * Address: 0x004A4260 (FUN_004A4260)
     *
     * What it does:
     * Lists `ref`'s fields under `parent`, each with its value and description,
     * then its elements as "[i] = " rows. A field is editable when both of its
     * low flag bits are set; an element when `parent` is.
     */
    void AddChildren(const wxTreeItemId& parent, const gpg::RRef& ref);

    /**
     * Address: 0x004A45C0 (FUN_004A45C0)
     *
     * What it does:
     * Writes `value` into mActiveItem's reference and shows the value back as
     * the type prints it. Nothing in the image calls this, and nothing ever
     * sets mActiveItem.
     */
    void SetValue(const wxString& value);

    /**
     * Address: 0x004A4530 (FUN_004A4530)
     *
     * What it does:
     * Destroys the dialog.
     */
    void OnClose(wxCloseEvent& event);

    /**
     * Address: 0x004A4540 (FUN_004A4540)
     *
     * What it does:
     * Lists the row's children the first time it opens.
     */
    void OnItemExpanding(wxTreeEvent& event);

    /**
     * Address: 0x004A4580 (FUN_004A4580)
     *
     * What it does:
     * Starts editing an editable row's Value column.
     */
    void OnItemActivated(wxTreeEvent& event);

    /**
     * Address: 0x004A46E0 (FUN_004A46E0)
     *
     * What it does:
     * Vetoes editing a row that is not editable.
     */
    void OnBeginLabelEdit(wxTreeEvent& event);

    /**
     * Address: 0x004A4710 (FUN_004A4710)
     *
     * What it does:
     * Writes the edited text into the row's reference unless the edit was
     * cancelled. The tree keeps the text as typed.
     */
    void OnEndLabelEdit(wxTreeEvent& event);

    wxTreeListCtrl* mTree;    // +0x170
    wxTreeItemId mActiveItem; // +0x174

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(WRefEditDialog, mTree) == 0x170, "WRefEditDialog::mTree offset must be 0x170");
  static_assert(offsetof(WRefEditDialog, mActiveItem) == 0x174, "WRefEditDialog::mActiveItem offset must be 0x174");
  static_assert(sizeof(WRefEditDialog) == 0x178, "WRefEditDialog size must be 0x178");
} // namespace moho

namespace
{
  // wxTR_ROW_LINES | wxTR_EDIT_LABELS on top of the watch panes' style: a
  // grid of rows whose labels can be edited.
  constexpr long kRefTreeStyle = wxTR_HAS_BUTTONS | wxTR_LINES_AT_ROOT | wxTR_EDIT_LABELS | wxTR_ROW_LINES
    | wxTR_HIDE_ROOT | wxTR_FULL_ROW_HIGHLIGHT;
} // namespace

// Table 0x00DFFB08 = {&wxDialog::sm_eventTable (0x00D540E8), rows 0x00F59378};
// GetEventTable (0x004A3DA0) comes with it.
BEGIN_EVENT_TABLE(moho::WRefEditDialog, wxDialog)
  EVT_CLOSE(moho::WRefEditDialog::OnClose)
  EVT_TREE_ITEM_EXPANDING(-1, moho::WRefEditDialog::OnItemExpanding)
  EVT_TREE_ITEM_ACTIVATED(-1, moho::WRefEditDialog::OnItemActivated)
  EVT_TREE_BEGIN_LABEL_EDIT(-1, moho::WRefEditDialog::OnBeginLabelEdit)
  EVT_TREE_END_LABEL_EDIT(-1, moho::WRefEditDialog::OnEndLabelEdit)
END_EVENT_TABLE()

/**
 * Address: 0x004A3CB0 (FUN_004A3CB0)
 */
moho::CRefTreeItemData::CRefTreeItemData(const gpg::RRef& ref, const bool editable, const msvc8::string& name)
  : mRef(ref)
  , mEditable(editable)
  , mName(name)
  , mPopulated(false)
{
}

/**
 * Address: 0x004A3DB0 (FUN_004A3DB0, ??0WRefEditDialog@Moho@@QAE@@Z)
 */
moho::WRefEditDialog::WRefEditDialog(const gpg::RRef& ref, const char* const name)
  : wxDialog(
      nullptr, -1, wxString(name, wxConvUTF8), wxDefaultPosition, wxSize(640, 480),
      wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER
    )
{
  mTree = new wxTreeListCtrl(this, -1, wxDefaultPosition, wxDefaultSize, kRefTreeStyle);
  mTree->AddColumn(wxT("Property"), 200, true);
  mTree->AddColumn(wxT("Value"), 200, false);
  mTree->AddColumn(wxT("Description"), 600, false);
  mTree->Expand(AddItem(wxTreeItemId(), "", ref, true));

  wxBoxSizer* const sizer = new wxBoxSizer(wxVERTICAL);
  sizer->Add(mTree, 1, wxEXPAND | wxALL, 0);
  SetSizer(sizer);
  Layout();
}

/**
 * Address: 0x004A4110 (FUN_004A4110)
 */
wxTreeItemId moho::WRefEditDialog::AddItem(
  const wxTreeItemId& parent, const msvc8::string& name, const gpg::RRef& ref, const bool editable
)
{
  const wxString label(name.c_str(), wxConvUTF8);
  wxTreeItemId item;
  if (parent.IsOk()) {
    item = mTree->AppendItem(parent, label);
  } else {
    item = mTree->AddRoot(label);
  }
  mTree->SetItemData(item, new CRefTreeItemData(ref, editable, name));

  const gpg::RIndexed* const indexed = ref.IsIndexed();
  if (ref.GetNumFields() != 0 || (indexed != nullptr && indexed->GetCount(ref.mObj) != 0)) {
    mTree->SetItemHasChildren(item, true);
  }
  return item;
}

/**
 * Address: 0x004A4260 (FUN_004A4260)
 */
void moho::WRefEditDialog::AddChildren(const wxTreeItemId& parent, const gpg::RRef& ref)
{
  const int fieldCount = ref.GetNumFields();
  for (int i = 0; i < fieldCount; ++i) {
    const gpg::RField& field = ref.mType->fields_[i];
    const gpg::RRef value = ref.GetField(i);
    const wxTreeItemId item = AddItem(parent, field.mName, value, (field.mFlags & 3) == 3);
    mTree->SetItemText(item, 1, wxString(value.GetLexical().c_str(), wxConvUTF8));
    mTree->SetItemText(item, 2, wxString(field.mDesc, wxConvUTF8));
  }

  if (ref.IsIndexed() != nullptr) {
    const CRefTreeItemData* const parentData = static_cast<CRefTreeItemData*>(mTree->GetItemData(parent));
    // The count and index are signed in the binary (jle/jl).
    const int count = static_cast<int>(ref.GetCount());
    for (int i = 0; i < count; ++i) {
      AddItem(parent, gpg::STR_Printf("[%d] = ", i), ref[i], parentData->mEditable);
    }
  }
}

/**
 * Address: 0x004A45C0 (FUN_004A45C0)
 */
void moho::WRefEditDialog::SetValue(const wxString& value)
{
  const CRefTreeItemData* const data = static_cast<CRefTreeItemData*>(mTree->GetItemData(mActiveItem));
  const msvc8::string text = gpg::STR_WideToUtf8(value.c_str());
  data->mRef.SetLexical(text.c_str());
  mTree->SetItemText(mActiveItem, 1, wxString(data->mRef.GetLexical().c_str(), wxConvUTF8));
}

/**
 * Address: 0x004A4530 (FUN_004A4530)
 */
void moho::WRefEditDialog::OnClose(wxCloseEvent& event)
{
  Destroy();
}

/**
 * Address: 0x004A4540 (FUN_004A4540)
 */
void moho::WRefEditDialog::OnItemExpanding(wxTreeEvent& event)
{
  const wxTreeItemId item = event.GetItem();
  CRefTreeItemData* const data = static_cast<CRefTreeItemData*>(mTree->GetItemData(item));
  if (!data->mPopulated) {
    data->mPopulated = true;
    AddChildren(item, data->mRef);
  }
}

/**
 * Address: 0x004A4580 (FUN_004A4580)
 */
void moho::WRefEditDialog::OnItemActivated(wxTreeEvent& event)
{
  const wxTreeItemId item = event.GetItem();
  const CRefTreeItemData* const data = static_cast<CRefTreeItemData*>(mTree->GetItemData(item));
  if (data->mEditable) {
    mTree->EditLabel(item, 1);
  }
}

/**
 * Address: 0x004A46E0 (FUN_004A46E0)
 */
void moho::WRefEditDialog::OnBeginLabelEdit(wxTreeEvent& event)
{
  const CRefTreeItemData* const data = static_cast<CRefTreeItemData*>(mTree->GetItemData(event.GetItem()));
  if (!data->mEditable) {
    event.Veto();
  }
}

/**
 * Address: 0x004A4710 (FUN_004A4710)
 */
void moho::WRefEditDialog::OnEndLabelEdit(wxTreeEvent& event)
{
  const CRefTreeItemData* const data = static_cast<CRefTreeItemData*>(mTree->GetItemData(event.GetItem()));
  if (!event.IsEditCancelled()) {
    data->mRef.SetLexical(gpg::STR_WideToUtf8(event.GetLabel().c_str()).c_str());
  }
}

/**
 * Address: 0x004A47C0 (FUN_004A47C0, ?REF_CreateEditDialog@Moho@@YAXPAVwxWindow@@ABVRRef@gpg@@PBD_N@Z)
 */
void moho::REF_CreateEditDialog(
  [[maybe_unused]] wxWindow* const parent, const gpg::RRef& ref, const char* const name, const bool
)
{
  WRefEditDialog* const dialog = new WRefEditDialog(ref, name);
  dialog->Show(true);
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
  // The binary passes only the reference and the name (0x008D40FC): the
  // parent and the flag are dropped, so their values are not recorded.
  REF_CreateEditDialog(nullptr, blueprintRef, blueprint->mBlueprintId.c_str(), false);
}
