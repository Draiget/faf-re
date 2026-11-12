// Engine addition (dedicated-server plan WPL.4, WPR.11): the reflection editor
// window (WRefEditDialog over one reflected object) and the SC_CreateEntityDialog
// console command that opens it on the selected unit's blueprint, moved out of
// Sim.cpp: both are user-side window code. A window-library dialog with a tree list in the
// binary; Dear ImGui in a window of its own since issue #414.

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "imgui.h"

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"
#include "platform/sdl/ToolWindow.h"

using namespace moho;

namespace
{
  [[nodiscard]] IUnit* ResolveIUnitBridge(
    UserUnit* const unit
  ) noexcept
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
   * Opens a modeless reflection editor on `ref`, titled `name`. The binary took a parent window
   * and a flag that nothing read: the dialog is always top-level, and the shipped code has both
   * dropped at the one call site.
   */
  void REF_CreateEditDialog(const gpg::RRef& ref, const char* name);

  /**
   * VFTABLE: 0x00E06F18 (??_7CRefTreeItemData@Moho@@6B@)
   *
   * One row of the reflection editor: the value it shows, whether its value may be edited, its
   * label, and whether its children have been listed. The binary's was the tree control's item
   * data; here the row also holds what the tree list's columns showed and its children.
   */
  class CRefTreeItemData
  {
  public:
    /**
     * Address: 0x004A3CB0 (FUN_004A3CB0)
     *
     * What it does:
     * Copies the row's reference, edit flag and label; its children are not listed yet.
     */
    CRefTreeItemData(const gpg::RRef& ref, bool editable, const fa::string& name);

    gpg::RRef mRef;
    bool mEditable;
    fa::string mName;
    bool mPopulated;
    bool mHasChildren = false;
    std::string mValue;       // the Value column
    std::string mDescription; // the Description column
    std::vector<std::unique_ptr<CRefTreeItemData>> mChildren;
  };

  /**
   * VFTABLE: 0x00E06F24 (??_7WRefEditDialog@Moho@@6B@)
   *
   * A modeless window over one reflected object: a tree of its fields and elements with their
   * values and field descriptions. Rows list their children the first time they are expanded,
   * and a writable field's value is edited in place (double-click the row, Enter to write it,
   * Escape to cancel), as the binary's tree list edited its Value column.
   */
  class WRefEditDialog final : public platform::tools::ToolWindow
  {
  public:
    /**
     * Address: 0x004A3DB0 (FUN_004A3DB0, ??0WRefEditDialog@Moho@@QAE@@Z)
     *
     * What it does:
     * A resizable 640x480 window titled `name`, filled by a Property/Value/Description tree
     * whose hidden root is `ref`.
     */
    WRefEditDialog(const gpg::RRef& ref, const char* name);

    /**
     * Address: 0x004A4110 (FUN_004A4110)
     *
     * What it does:
     * Adds a row for `ref` labelled `name` under `parent`, or as the root when there is no
     * parent. The row can be expanded when the value has fields or elements.
     */
    CRefTreeItemData* AddItem(CRefTreeItemData* parent, const fa::string& name, const gpg::RRef& ref, bool editable);

    /**
     * Address: 0x004A4260 (FUN_004A4260)
     *
     * What it does:
     * Lists `ref`'s fields under `parent`, each with its value and description, then its
     * elements as "[i] = " rows. A field is editable when both of its low flag bits are set; an
     * element when `parent` is.
     */
    void AddChildren(CRefTreeItemData* parent, const gpg::RRef& ref);

    /**
     * Address: 0x004A4710 (FUN_004A4710, OnEndLabelEdit)
     *
     * What it does:
     * Writes the edited text into the row's reference unless the edit was cancelled, then
     * shows the value as the type prints it back.
     */
    void EndEdit(bool cancelled);

  protected:
    void Tick() override;
    void Draw() override;
    /**
     * Address: 0x004A4530 (FUN_004A4530, OnClose)
     *
     * What it does:
     * Destroys the window.
     */
    void OnCloseRequested() override;

  private:
    void DrawRow(CRefTreeItemData& row);

    std::unique_ptr<CRefTreeItemData> mRoot;
    CRefTreeItemData* mActiveItem = nullptr; // the row whose value is being edited
    std::array<char, 512> mEditText{};
    bool mFocusEdit = false;
    bool mCloseRequested = false;
  };
} // namespace moho

/**
 * Address: 0x004A3CB0 (FUN_004A3CB0)
 */
moho::CRefTreeItemData::CRefTreeItemData(
  const gpg::RRef& ref,
  const bool editable,
  const fa::string& name
)
  : mRef(ref)
  , mEditable(editable)
  , mName(name)
  , mPopulated(false)
{}

/**
 * Address: 0x004A3DB0 (FUN_004A3DB0, ??0WRefEditDialog@Moho@@QAE@@Z)
 */
moho::WRefEditDialog::WRefEditDialog(
  const gpg::RRef& ref,
  const char* const name
)
  : platform::tools::ToolWindow(name, 640, 480)
{
  // The hidden root, expanded at once (mTree->Expand(AddItem(...)) in the binary).
  CRefTreeItemData* const root = AddItem(nullptr, "", ref, true);
  root->mPopulated = true;
  AddChildren(root, ref);
}

/**
 * Address: 0x004A4110 (FUN_004A4110)
 */
moho::CRefTreeItemData* moho::WRefEditDialog::AddItem(
  CRefTreeItemData* const parent,
  const fa::string& name,
  const gpg::RRef& ref,
  const bool editable
)
{
  auto item = std::make_unique<CRefTreeItemData>(ref, editable, name);
  const gpg::RIndexed* const indexed = ref.IsIndexed();
  item->mHasChildren = ref.GetNumFields() != 0 || (indexed != nullptr && indexed->GetCount(ref.mObj) != 0);
  CRefTreeItemData* const added = item.get();
  if (parent != nullptr) {
    parent->mChildren.push_back(std::move(item));
  } else {
    mRoot = std::move(item);
  }
  return added;
}

/**
 * Address: 0x004A4260 (FUN_004A4260)
 */
void moho::WRefEditDialog::AddChildren(
  CRefTreeItemData* const parent,
  const gpg::RRef& ref
)
{
  const int fieldCount = ref.GetNumFields();
  for (int i = 0; i < fieldCount; ++i) {
    const gpg::RField& field = ref.mType->fields_[i];
    const gpg::RRef value = ref.GetField(i);
    CRefTreeItemData* const item = AddItem(parent, field.mName, value, (field.mFlags & 3) == 3);
    item->mValue = value.GetLexical().c_str();
    item->mDescription = field.mDesc != nullptr ? field.mDesc : "";
  }

  if (ref.IsIndexed() != nullptr) {
    // The count and index are signed in the binary (jle/jl).
    const int count = static_cast<int>(ref.GetCount());
    for (int i = 0; i < count; ++i) {
      AddItem(parent, gpg::STR_Printf("[%d] = ", i), ref[i], parent->mEditable);
    }
  }
}

void moho::WRefEditDialog::EndEdit(
  const bool cancelled
)
{
  if (mActiveItem == nullptr) {
    return;
  }
  if (!cancelled) {
    mActiveItem->mRef.SetLexical(mEditText.data());
    mActiveItem->mValue = mActiveItem->mRef.GetLexical().c_str();
  }
  mActiveItem = nullptr;
}

void moho::WRefEditDialog::OnCloseRequested()
{
  mCloseRequested = true;
  Show(false);
}

void moho::WRefEditDialog::Tick()
{
  if (mCloseRequested) {
    delete this; // the binary's OnClose destroys the dialog
  }
}

void moho::WRefEditDialog::DrawRow(
  CRefTreeItemData& row
)
{
  ImGui::TableNextRow();
  ImGui::TableSetColumnIndex(0);
  ImGui::PushID(&row);
  ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanFullWidth | ImGuiTreeNodeFlags_OpenOnArrow;
  if (!row.mHasChildren) {
    flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
  }
  const bool open = ImGui::TreeNodeEx("##row", flags, "%s", row.mName.c_str());
  // Address: 0x004A4540 (FUN_004A4540, OnItemExpanding): the children are listed the first time.
  if (open && row.mHasChildren && !row.mPopulated) {
    row.mPopulated = true;
    AddChildren(&row, row.mRef);
  }
  // Address: 0x004A4580 (FUN_004A4580, OnItemActivated) and 0x004A46E0 (OnBeginLabelEdit): only
  // an editable row's value is edited.
  if (row.mEditable && ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
    EndEdit(true);
    mActiveItem = &row;
    std::snprintf(mEditText.data(), mEditText.size(), "%s", row.mValue.c_str());
    mFocusEdit = true;
  }

  ImGui::TableSetColumnIndex(1);
  if (mActiveItem == &row) {
    ImGui::SetNextItemWidth(-1.0f);
    if (mFocusEdit) {
      ImGui::SetKeyboardFocusHere();
      mFocusEdit = false;
    }
    if (ImGui::InputText("##value", mEditText.data(), mEditText.size(), ImGuiInputTextFlags_EnterReturnsTrue)) {
      EndEdit(false);
    } else if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      EndEdit(true);
    }
  } else {
    ImGui::TextUnformatted(row.mValue.c_str());
  }
  ImGui::TableSetColumnIndex(2);
  ImGui::TextUnformatted(row.mDescription.c_str());

  if (open && row.mHasChildren) {
    for (const std::unique_ptr<CRefTreeItemData>& child : row.mChildren) {
      DrawRow(*child);
    }
    ImGui::TreePop();
  }
  ImGui::PopID();
}

void moho::WRefEditDialog::Draw()
{
  constexpr ImGuiTableFlags kTableFlags = ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
    ImGuiTableFlags_BordersOuterH | ImGuiTableFlags_ScrollY;
  if (!ImGui::BeginTable("##ref", 3, kTableFlags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, 200.0f);
  ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 200.0f);
  ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
  ImGui::TableHeadersRow();
  if (mRoot != nullptr) {
    // The root row is hidden (TR_HIDE_ROOT): its children are the top rows.
    for (const std::unique_ptr<CRefTreeItemData>& child : mRoot->mChildren) {
      DrawRow(*child);
    }
  }
  ImGui::EndTable();
}

/**
 * Address: 0x004A47C0 (FUN_004A47C0, ?REF_CreateEditDialog@Moho@@YAXPAVwxWindow@@ABVRRef@gpg@@PBD_N@Z)
 */
void moho::REF_CreateEditDialog(
  const gpg::RRef& ref,
  const char* const name
)
{
  WRefEditDialog* const dialog = new WRefEditDialog(ref, name);
  if (!dialog->IsValid()) {
    delete dialog;
    return;
  }
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

  fa::vector<UserUnit*> selectedUnits{};
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
  REF_CreateEditDialog(blueprintRef, blueprint->mBlueprintId.c_str());
}
