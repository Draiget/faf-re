#include "WxRuntimeTypes.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <memory>
#include <new>
#include <system_error>
#include <unordered_map>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "moho/misc/StartupHelpers.h"
#include "moho/console/CConCommand.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace
{
  constexpr std::uintptr_t kInlineHeadLinkSentinelMax = 0x10000u;
  void* gCLogAdditionEventClassInfoTable[1] = {nullptr};
  void* gWxWindowBaseClassInfoTable[1] = {nullptr};
  void* gWxWindowClassInfoTable[1] = {nullptr};
  void* gWxImageHandlerClassInfoTable[1] = {nullptr};
  void* gWxPngHandlerClassInfoTable[1] = {nullptr};

  struct WxObjectRuntimeView
  {
    void* vtable = nullptr;
    void* refData = nullptr;
  };

  /**
   * Address: 0x0042B9D0 (FUN_0042B9D0)
   *
   * What it does:
   * Shared wx-object unref tail used by destructor paths that only clear
   * ref-data ownership.
   */
  void RunWxObjectUnrefTail(WxObjectRuntimeView* const object) noexcept
  {
    if (object == nullptr) {
      return;
    }
    object->refData = nullptr;
  }

  void ReleaseWxStringSharedPayload(wxStringRuntime& value) noexcept
  {
    std::int32_t* const sharedPrefixWords = reinterpret_cast<std::int32_t*>(value.m_pchData) - 3;
    const std::int32_t sharedRefCount = sharedPrefixWords[0];
    if (sharedRefCount != -1) {
      sharedPrefixWords[0] = sharedRefCount - 1;
      if (sharedRefCount == 1) {
        ::operator delete(sharedPrefixWords);
      }
    }
  }

  void ReleaseD3DDeviceRef(void* const device) noexcept
  {
    if (device == nullptr) {
      return;
    }

    void** const vtable = *reinterpret_cast<void***>(device);
    if (vtable == nullptr || vtable[1] == nullptr) {
      return;
    }

    using ReleaseFn = void(__thiscall*)(void*, unsigned int);
    auto const release = reinterpret_cast<ReleaseFn>(vtable[1]);
    release(device, 1u);
  }

  [[nodiscard]] bool IsInlineHeadLinkSentinel(moho::ManagedWindowSlot** const ownerHeadLink) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(ownerHeadLink) < kInlineHeadLinkSentinelMax;
  }

  [[nodiscard]] moho::ManagedWindowSlot* TranslateSlotPointerForReallocation(
    moho::ManagedWindowSlot* const pointer,
    const moho::ManagedWindowSlot* const oldStorage,
    const std::size_t oldCount,
    moho::ManagedWindowSlot* const newStorage
  ) noexcept
  {
    if (pointer == nullptr || oldStorage == nullptr || oldCount == 0 || newStorage == nullptr) {
      return pointer;
    }

    const std::uintptr_t oldBegin = reinterpret_cast<std::uintptr_t>(oldStorage);
    const std::uintptr_t oldEnd = oldBegin + oldCount * sizeof(moho::ManagedWindowSlot);
    const std::uintptr_t pointerValue = reinterpret_cast<std::uintptr_t>(pointer);
    if (pointerValue < oldBegin || pointerValue >= oldEnd) {
      return pointer;
    }

    const std::size_t index = (pointerValue - oldBegin) / sizeof(moho::ManagedWindowSlot);
    return &newStorage[index];
  }

  void RebaseManagedSlotPointersAfterReallocation(
    msvc8::vector<moho::ManagedWindowSlot>& slots,
    const moho::ManagedWindowSlot* const oldStorage,
    const std::size_t oldCount
  ) noexcept
  {
    if (oldStorage == nullptr || oldCount == 0) {
      return;
    }

    moho::ManagedWindowSlot* const newStorage = slots.data();
    if (newStorage == nullptr || newStorage == oldStorage) {
      return;
    }

    const std::size_t newCount = slots.size();
    for (std::size_t index = 0; index < newCount; ++index) {
      moho::ManagedWindowSlot& slot = newStorage[index];
      slot.nextInOwnerChain =
        TranslateSlotPointerForReallocation(slot.nextInOwnerChain, oldStorage, oldCount, newStorage);
    }

    for (std::size_t index = 0; index < newCount; ++index) {
      moho::ManagedWindowSlot& slot = newStorage[index];
      if (slot.ownerHeadLink == nullptr || IsInlineHeadLinkSentinel(slot.ownerHeadLink)) {
        continue;
      }

      moho::ManagedWindowSlot* const translatedHead =
        TranslateSlotPointerForReallocation(*slot.ownerHeadLink, oldStorage, oldCount, newStorage);
      if (*slot.ownerHeadLink != translatedHead) {
        *slot.ownerHeadLink = translatedHead;
      }
    }
  }

  void DetachSlotWithoutClearing(moho::ManagedWindowSlot& slot) noexcept
  {
    if (slot.ownerHeadLink == nullptr || IsInlineHeadLinkSentinel(slot.ownerHeadLink)) {
      return;
    }

    moho::ManagedWindowSlot** link = slot.ownerHeadLink;
    while (*link != nullptr && *link != &slot) {
      link = &(*link)->nextInOwnerChain;
    }

    if (*link == &slot) {
      *link = slot.nextInOwnerChain;
    }
  }

  void RelinkSlotToOwner(moho::ManagedWindowSlot& slot, moho::ManagedWindowSlot** const ownerHeadLink) noexcept
  {
    if (slot.ownerHeadLink == ownerHeadLink) {
      return;
    }

    DetachSlotWithoutClearing(slot);
    slot.ownerHeadLink = ownerHeadLink;
    if (ownerHeadLink == nullptr) {
      slot.nextInOwnerChain = nullptr;
      return;
    }

    slot.nextInOwnerChain = *ownerHeadLink;
    *ownerHeadLink = &slot;
  }

  template <typename TOwnerRuntime>
  [[nodiscard]] bool IsReusableManagedSlot(const moho::ManagedWindowSlot& slot)
  {
    return slot.ownerHeadLink == nullptr || slot.ownerHeadLink == TOwnerRuntime::NullManagedSlotHeadLinkSentinel();
  }

  template <typename TOwnerRuntime>
  [[nodiscard]] bool TryReuseManagedSlot(
    msvc8::vector<moho::ManagedWindowSlot>& slots, moho::ManagedWindowSlot** const ownerHeadLink
  )
  {
    moho::ManagedWindowSlot* const slotStorage = slots.data();
    if (slotStorage == nullptr) {
      return false;
    }

    const std::size_t slotCount = slots.size();
    for (std::size_t index = 0; index < slotCount; ++index) {
      moho::ManagedWindowSlot& slot = slotStorage[index];
      if (!IsReusableManagedSlot<TOwnerRuntime>(slot)) {
        continue;
      }

      RelinkSlotToOwner(slot, ownerHeadLink);
      return true;
    }

    return false;
  }

  template <typename TOwnerRuntime>
  void AppendManagedSlot(
    msvc8::vector<moho::ManagedWindowSlot>& slots, moho::ManagedWindowSlot** const ownerHeadLink
  )
  {
    if (ownerHeadLink == nullptr) {
      return;
    }

    moho::ManagedWindowSlot appendedSlot{};
    appendedSlot.ownerHeadLink = ownerHeadLink;
    appendedSlot.nextInOwnerChain = *ownerHeadLink;

    moho::ManagedWindowSlot* const oldStorage = slots.data();
    const std::size_t oldCount = slots.size();
    slots.push_back(appendedSlot);

    RebaseManagedSlotPointersAfterReallocation(slots, oldStorage, oldCount);

    moho::ManagedWindowSlot* const slotStorage = slots.data();
    if (slotStorage == nullptr || slots.empty()) {
      return;
    }

    moho::ManagedWindowSlot& insertedSlot = slotStorage[slots.size() - 1];
    insertedSlot.ownerHeadLink = ownerHeadLink;
    *ownerHeadLink = &insertedSlot;
  }

  template <typename TOwnerRuntime>
  void RegisterManagedOwnerSlotImpl(
    msvc8::vector<moho::ManagedWindowSlot>& slots, moho::ManagedWindowSlot** const ownerHeadLink
  )
  {
    if (ownerHeadLink == nullptr) {
      return;
    }

    if (TryReuseManagedSlot<TOwnerRuntime>(slots, ownerHeadLink)) {
      return;
    }

    AppendManagedSlot<TOwnerRuntime>(slots, ownerHeadLink);
  }

  void ReleaseManagedOwnerSlotChain(moho::ManagedWindowSlot*& ownerHead) noexcept
  {
    while (ownerHead != nullptr) {
      moho::ManagedWindowSlot* const slot = ownerHead;
      ownerHead = slot->nextInOwnerChain;
      slot->Clear();
    }
  }

  template <typename TOwnerRuntime>
  void DestroyManagedRuntimeCollection(msvc8::vector<moho::ManagedWindowSlot>& slots)
  {
    for (std::size_t index = 0;; ++index) {
      moho::ManagedWindowSlot* slotStorage = slots.data();
      const std::size_t slotCount = slots.size();
      if (slotStorage == nullptr || index >= slotCount) {
        break;
      }

      moho::ManagedWindowSlot& slot = slotStorage[index];
      if (slot.ownerHeadLink == nullptr || slot.ownerHeadLink == TOwnerRuntime::NullManagedSlotHeadLinkSentinel()) {
        continue;
      }

      TOwnerRuntime* const owner = TOwnerRuntime::FromManagedSlotHeadLink(slot.ownerHeadLink);
      if (owner != nullptr) {
        (void)owner->Destroy();
      }

      slotStorage = slots.data();
      if (slotStorage == nullptr || index >= slots.size()) {
        continue;
      }
      slotStorage[index].UnlinkFromOwner();
    }
  }

  struct SupComFrameState
  {
    std::int32_t clientWidth = 0;
    std::int32_t clientHeight = 0;
    std::int32_t minWidth = 0;
    std::int32_t minHeight = 0;
    std::int32_t windowX = -1;
    std::int32_t windowY = -1;
    std::int32_t windowStyle = 0;
    bool visible = false;
    bool maximized = false;
    bool focused = false;
    bool iconized = false;
    bool iconResourceAssigned = false;
    std::uintptr_t pseudoWindowHandle = 0;
    std::wstring title;
    std::wstring name;
    std::wstring iconResourceName;
  };

  constexpr std::uintptr_t kFirstSupComFramePseudoHandle = 0x1000u;
  constexpr std::uintptr_t kSupComFramePseudoHandleStride = 0x10u;
  constexpr wchar_t kSupComFrameWindowName[] = L"frame";
  constexpr wchar_t kSupComFrameIconResourceName[] = L"ID";

  std::uintptr_t gNextSupComFramePseudoHandle = kFirstSupComFramePseudoHandle;
  std::unordered_map<const WSupComFrame*, SupComFrameState> gSupComFrameStateByFrame{};
  struct WxTopLevelWindowRuntimeState
  {
    std::int32_t fsOldX = 0;
    std::int32_t fsOldY = 0;
    std::int32_t fsOldWidth = 0;
    std::int32_t fsOldHeight = 0;
    std::uint8_t flag34 = 0;
  };

  struct WxDialogRuntimeState
  {
    void* parentWindow = nullptr;
    std::int32_t windowId = -1;
    wxPoint position{};
    wxSize size{};
    long style = 0;
    std::wstring title{};
    std::wstring name{};
  };

  std::unordered_map<const wxTopLevelWindowRuntime*, WxTopLevelWindowRuntimeState>
    gWxTopLevelWindowRuntimeStateByWindow{};
  std::unordered_map<const wxDialogRuntime*, WxDialogRuntimeState> gWxDialogRuntimeStateByDialog{};

  struct WxTreeListNodeRuntimeState
  {
    WxTreeListNodeRuntimeState* parent = nullptr;
    std::vector<WxTreeListNodeRuntimeState*> children{};
    wxTreeItemDataRuntime* itemData = nullptr;
    bool hasChildrenFlag = false;
    bool isExpanded = false;
    std::vector<msvc8::string> columnText{};
  };

  struct WxTreeListRuntimeState
  {
    wxWindowBase* parentWindow = nullptr;
    std::int32_t windowId = -1;
    wxPoint position{};
    wxSize size{};
    long style = 0;
    std::wstring name{};
    std::vector<wxTreeListColumnInfoRuntime> columns{};
    std::vector<std::unique_ptr<WxTreeListNodeRuntimeState>> nodeStorage{};
    WxTreeListNodeRuntimeState* rootNode = nullptr;
  };

  std::unordered_map<const wxTreeListCtrlRuntime*, WxTreeListRuntimeState> gWxTreeListRuntimeStateByControl{};

  struct WxWindowBaseRuntimeState
  {
    std::int32_t minWidth = -1;
    std::int32_t minHeight = -1;
    std::int32_t maxWidth = -1;
    std::int32_t maxHeight = -1;
    long windowStyle = 0;
    long extraStyle = 0;
    unsigned long nativeHandle = 0;
    std::int32_t windowId = -1;
    wxWindowBase* parentWindow = nullptr;
    bool themeEnabled = false;
    std::uint8_t bitfields = 0;
    std::wstring windowName{};
    void* dropTarget = nullptr;
  };

  std::unordered_map<const wxWindowBase*, WxWindowBaseRuntimeState> gWxWindowBaseStateByWindow{};
  wxWindowBase* gCapturedWindow = nullptr;
  bool gSplashPngHandlerInitialized = false;

  [[nodiscard]] std::uintptr_t AllocateSupComFramePseudoHandle() noexcept
  {
    const std::uintptr_t handle = gNextSupComFramePseudoHandle;
    gNextSupComFramePseudoHandle += kSupComFramePseudoHandleStride;
    return handle;
  }

  [[nodiscard]] SupComFrameState* FindSupComFrameState(const WSupComFrame* const frame) noexcept
  {
    const auto it = gSupComFrameStateByFrame.find(frame);
    return it != gSupComFrameStateByFrame.end() ? &it->second : nullptr;
  }

  [[nodiscard]] const WxTopLevelWindowRuntimeState* FindWxTopLevelWindowRuntimeState(
    const wxTopLevelWindowRuntime* const window
  ) noexcept
  {
    const auto it = gWxTopLevelWindowRuntimeStateByWindow.find(window);
    return it != gWxTopLevelWindowRuntimeStateByWindow.end() ? &it->second : nullptr;
  }

  [[nodiscard]] WxTopLevelWindowRuntimeState& EnsureWxTopLevelWindowRuntimeState(
    const wxTopLevelWindowRuntime* const window
  )
  {
    return gWxTopLevelWindowRuntimeStateByWindow[window];
  }

  [[nodiscard]] WxDialogRuntimeState& EnsureWxDialogRuntimeState(const wxDialogRuntime* const dialog)
  {
    return gWxDialogRuntimeStateByDialog[dialog];
  }

  [[nodiscard]] WxTreeListRuntimeState& EnsureWxTreeListRuntimeState(const wxTreeListCtrlRuntime* const treeControl)
  {
    return gWxTreeListRuntimeStateByControl[treeControl];
  }

  [[nodiscard]] const WxTreeListRuntimeState* FindWxTreeListRuntimeState(
    const wxTreeListCtrlRuntime* const treeControl
  ) noexcept
  {
    const auto it = gWxTreeListRuntimeStateByControl.find(treeControl);
    return it != gWxTreeListRuntimeStateByControl.end() ? &it->second : nullptr;
  }

  [[nodiscard]] WxTreeListNodeRuntimeState* AllocateTreeListNode(
    WxTreeListRuntimeState& state,
    WxTreeListNodeRuntimeState* const parentNode,
    const msvc8::string& rootText
  )
  {
    auto node = std::make_unique<WxTreeListNodeRuntimeState>();
    node->parent = parentNode;
    node->columnText.resize(3);
    node->columnText[0] = rootText;

    WxTreeListNodeRuntimeState* const rawNode = node.get();
    state.nodeStorage.push_back(std::move(node));
    if (parentNode != nullptr) {
      parentNode->children.push_back(rawNode);
    }
    return rawNode;
  }

  [[nodiscard]] WxTreeListNodeRuntimeState* ResolveTreeListNode(const wxTreeItemIdRuntime& item) noexcept
  {
    return static_cast<WxTreeListNodeRuntimeState*>(item.mNode);
  }

  [[nodiscard]] const WxTreeListNodeRuntimeState* ResolveTreeListNodeConst(const wxTreeItemIdRuntime& item) noexcept
  {
    return static_cast<const WxTreeListNodeRuntimeState*>(item.mNode);
  }

  [[nodiscard]] const WxWindowBaseRuntimeState* FindWxWindowBaseRuntimeState(
    const wxWindowBase* const window
  ) noexcept
  {
    const auto it = gWxWindowBaseStateByWindow.find(window);
    return it != gWxWindowBaseStateByWindow.end() ? &it->second : nullptr;
  }

  [[nodiscard]] WxWindowBaseRuntimeState& EnsureWxWindowBaseRuntimeState(const wxWindowBase* const window)
  {
    return gWxWindowBaseStateByWindow[window];
  }

  [[nodiscard]] SupComFrameState& EnsureSupComFrameState(const WSupComFrame* const frame)
  {
    return gSupComFrameStateByFrame[frame];
  }

  class WSupComFrameRuntime final : public WSupComFrame
  {
  public:
    WSupComFrameRuntime(
      const char* const titleUtf8,
      const wxPoint& initialPosition,
      const wxSize& initialClientSize,
      const std::int32_t style
    )
    {
      mPendingMaximizeSync = 0;
      mPersistedMaximizeSync = 0;
      mIsApplicationActive = 0;

      SupComFrameState& state = EnsureSupComFrameState(this);
      state.clientWidth = initialClientSize.x > 0 ? initialClientSize.x : 0;
      state.clientHeight = initialClientSize.y > 0 ? initialClientSize.y : 0;
      state.windowX = initialPosition.x;
      state.windowY = initialPosition.y;
      state.windowStyle = style;
      state.pseudoWindowHandle = AllocateSupComFramePseudoHandle();
      state.title = gpg::STR_Utf8ToWide(titleUtf8 != nullptr ? titleUtf8 : "");
      state.name.assign(kSupComFrameWindowName);
      state.iconResourceName.assign(kSupComFrameIconResourceName);
      state.iconResourceAssigned = true;
    }

    bool Destroy() override
    {
      gWxTopLevelWindowRuntimeStateByWindow.erase(this);
      gWxWindowBaseStateByWindow.erase(this);
      gSupComFrameStateByFrame.erase(this);
      delete this;
      return true;
    }

    bool Show(const bool show) override
    {
      EnsureSupComFrameState(this).visible = show;
      return true;
    }

    void SetTitle(const wxStringRuntime& title) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.title.assign(title.c_str());
    }

    void SetName(const wxStringRuntime& name) override
    {
      wxWindowBase::SetName(name);
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.name.assign(name.c_str());
    }

    void SetWindowStyleFlag(const long style) override
    {
      EnsureSupComFrameState(this).windowStyle = static_cast<std::int32_t>(style);
    }

    [[nodiscard]] long GetWindowStyleFlag() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr ? state->windowStyle : 0;
    }

    void SetSizeHints(
      const std::int32_t minWidth,
      const std::int32_t minHeight,
      const std::int32_t maxWidth,
      const std::int32_t maxHeight,
      const std::int32_t incWidth,
      const std::int32_t incHeight
    ) override
    {
      (void)maxWidth;
      (void)maxHeight;
      (void)incWidth;
      (void)incHeight;

      SupComFrameState& state = EnsureSupComFrameState(this);
      state.minWidth = minWidth > 0 ? minWidth : 0;
      state.minHeight = minHeight > 0 ? minHeight : 0;
      if (state.clientWidth < state.minWidth) {
        state.clientWidth = state.minWidth;
      }
      if (state.clientHeight < state.minHeight) {
        state.clientHeight = state.minHeight;
      }
    }

    void SetFocus() override
    {
      EnsureSupComFrameState(this).focused = true;
    }

    [[nodiscard]] unsigned long GetHandle() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr ? static_cast<unsigned long>(state->pseudoWindowHandle) : 0u;
    }

    void DoGetClientSize(std::int32_t* const outWidth, std::int32_t* const outHeight) const override
    {
      if (outWidth != nullptr) {
        *outWidth = 0;
      }
      if (outHeight != nullptr) {
        *outHeight = 0;
      }

      const SupComFrameState* const state = FindSupComFrameState(this);
      if (state == nullptr) {
        return;
      }

      if (outWidth != nullptr) {
        *outWidth = state->clientWidth;
      }
      if (outHeight != nullptr) {
        *outHeight = state->clientHeight;
      }
    }

    void DoSetClientSize(const std::int32_t width, const std::int32_t height) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      const std::int32_t requestedWidth = width > 0 ? width : 0;
      const std::int32_t requestedHeight = height > 0 ? height : 0;
      state.clientWidth = requestedWidth > state.minWidth ? requestedWidth : state.minWidth;
      state.clientHeight = requestedHeight > state.minHeight ? requestedHeight : state.minHeight;
    }

    void DoGetPosition(std::int32_t* const x, std::int32_t* const y) const override
    {
      if (x != nullptr) {
        *x = 0;
      }
      if (y != nullptr) {
        *y = 0;
      }

      const SupComFrameState* const state = FindSupComFrameState(this);
      if (state == nullptr) {
        return;
      }

      if (x != nullptr) {
        *x = state->windowX;
      }
      if (y != nullptr) {
        *y = state->windowY;
      }
    }

    void DoSetSize(
      const std::int32_t x,
      const std::int32_t y,
      const std::int32_t width,
      const std::int32_t height,
      const std::int32_t sizeFlags
    ) override
    {
      (void)sizeFlags;

      SupComFrameState& state = EnsureSupComFrameState(this);
      state.windowX = x;
      state.windowY = y;
      DoSetClientSize(width, height);
    }

    void Maximize(const bool maximize) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.maximized = maximize;
      mPendingMaximizeSync = maximize ? 1 : 0;
      mPersistedMaximizeSync = maximize ? 1 : 0;
    }

    void Iconize(const bool iconize) override
    {
      EnsureSupComFrameState(this).iconized = iconize;
    }

    [[nodiscard]] bool IsMaximized() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr && state->maximized;
    }

    [[nodiscard]] bool IsIconized() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr && state->iconized;
    }

    void SetIcon(const void* const icon) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.iconResourceAssigned = icon != nullptr;
      if (state.iconResourceAssigned) {
        state.iconResourceName.assign(kSupComFrameIconResourceName);
      } else {
        state.iconResourceName.clear();
      }
    }

    void SetIcons(const void* const iconBundle) override
    {
      SetIcon(iconBundle);
    }
  };

  struct DwordLaneRuntimeView
  {
    std::uint32_t lane00 = 0;
  };

  static_assert(offsetof(DwordLaneRuntimeView, lane00) == 0x0, "DwordLaneRuntimeView::lane00 offset must be 0x0");
  static_assert(sizeof(DwordLaneRuntimeView) == 0x4, "DwordLaneRuntimeView size must be 0x4");

  /**
   * Address: 0x004A3670 (FUN_004A3670)
   *
   * What it does:
   * Returns the leading 32-bit lane from one unknown runtime pod view.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadRuntimeDwordLaneA(const DwordLaneRuntimeView* const view) noexcept
  {
    return view->lane00;
  }

  /**
   * Address: 0x004A3680 (FUN_004A3680)
   *
   * What it does:
   * Returns the leading 32-bit lane from one unknown runtime pod view.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadRuntimeDwordLaneB(const DwordLaneRuntimeView* const view) noexcept
  {
    return view->lane00;
  }

  struct FourDwordBlockRuntimeView
  {
    std::int32_t lane00 = 0;
    std::int32_t lane04 = 0;
    std::int32_t lane08 = 0;
    std::int32_t lane0C = 0;
  };

  static_assert(sizeof(FourDwordBlockRuntimeView) == 0x10, "FourDwordBlockRuntimeView size must be 0x10");

  /**
   * Address: 0x004A36D0 (FUN_004A36D0)
   *
   * What it does:
   * Clears one four-dword runtime block used by wx region rectangle vectors.
   */
  [[maybe_unused]] void ClearFourDwordBlock(FourDwordBlockRuntimeView* const view) noexcept
  {
    view->lane00 = 0;
    view->lane04 = 0;
    view->lane08 = 0;
    view->lane0C = 0;
  }

  class SplashScreenRuntimeImpl final : public moho::SplashScreenRuntime
  {
  public:
    SplashScreenRuntimeImpl(const msvc8::string& imagePath, const wxSize& size)
      : mImagePath(imagePath)
      , mSize(size)
    {
    }

    void GetClassInfo() override
    {
    }

    void DeleteObject(const std::uint32_t flags) override
    {
      if ((flags & 1u) != 0u) {
        delete this;
      }
    }

  private:
    msvc8::string mImagePath;
    wxSize mSize{};
  };
} // namespace

void* wxTopLevelWindowRootRuntime::sm_classInfo[1] = {nullptr};

/**
 * Address: 0x004A3690 (FUN_004A3690)
 * Mangled: ??0wxClientData@@QAE@@Z
 *
 * What it does:
 * Constructs one `wxClientData` runtime lane.
 */
wxClientDataRuntime::wxClientDataRuntime()
{
  ResetRuntimeVTable();
}

/**
 * Address: 0x004A36A0 (FUN_004A36A0)
 *
 * What it does:
 * Rebinds this object to the `wxClientData` runtime vtable lane.
 */
void wxClientDataRuntime::ResetRuntimeVTable() noexcept
{
}

/**
 * Address: 0x004A36B0 (FUN_004A36B0)
 *
 * What it does:
 * Implements the deleting-dtor thunk lane for `wxClientData`.
 */
wxClientDataRuntime* wxClientDataRuntime::DeleteWithFlag(
  wxClientDataRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->ResetRuntimeVTable();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A3710 (FUN_004A3710)
 * Mangled: ??0wxTopLevelWindowMSW@@QAE@@Z
 *
 * What it does:
 * Constructs one top-level-window runtime base lane and resets fullscreen
 * state bookkeeping.
 */
wxTopLevelWindowRuntime::wxTopLevelWindowRuntime()
{
  WxTopLevelWindowRuntimeState& state = EnsureWxTopLevelWindowRuntimeState(this);
  state.fsOldX = 0;
  state.fsOldY = 0;
  state.fsOldWidth = 0;
  state.fsOldHeight = 0;
  ResetTopLevelFlag34();
}

/**
 * Address: 0x004A36E0 (FUN_004A36E0)
 *
 * What it does:
 * Resets one top-level-window runtime flag lane.
 */
void wxTopLevelWindowRuntime::ResetTopLevelFlag34() noexcept
{
  EnsureWxTopLevelWindowRuntimeState(this).flag34 = 0;
}

/**
 * Address: 0x004A36F0 (FUN_004A36F0)
 * Mangled: ?IsTopLevel@wxTopLevelWindowBase@@UBE_NXZ
 *
 * What it does:
 * Reports this runtime lane as a top-level wx window.
 */
bool wxTopLevelWindowRuntime::IsTopLevel() const
{
  return true;
}

/**
 * Address: 0x004A3700 (FUN_004A3700)
 * Mangled: ?IsOneOfBars@wxTopLevelWindowBase@@MBE_NPBVwxWindow@@@Z
 *
 * What it does:
 * Base implementation reports the queried window as not one of frame bars.
 */
bool wxTopLevelWindowRuntime::IsOneOfBars(const void* const window) const
{
  (void)window;
  return false;
}

/**
 * Address: 0x004A3770 (FUN_004A3770)
 * Mangled: ?IsFullScreen@wxTopLevelWindowMSW@@UBE_NXZ
 *
 * What it does:
 * Returns one cached fullscreen-visible flag.
 */
bool wxTopLevelWindowRuntime::IsFullScreen() const
{
  const WxTopLevelWindowRuntimeState* const state = FindWxTopLevelWindowRuntimeState(this);
  return state != nullptr && state->flag34 != 0;
}

/**
 * Address: 0x004A3780 (FUN_004A3780)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for top-level-window runtime
 * lanes.
 */
wxTopLevelWindowRuntime* wxTopLevelWindowRuntime::DeleteWithFlag(
  wxTopLevelWindowRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxTopLevelWindowRuntimeStateByWindow.erase(object);
  object->~wxTopLevelWindowRuntime();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A37A0 (FUN_004A37A0)
 * Mangled: ??0wxTopLevelWindow@@QAE@@Z
 *
 * What it does:
 * Constructs one `wxTopLevelWindow` runtime layer and reapplies base
 * top-level init.
 */
wxTopLevelWindowRootRuntime::wxTopLevelWindowRootRuntime()
  : wxTopLevelWindowRuntime()
{
  ResetTopLevelFlag34();
}

/**
 * Address: 0x004A3800 (FUN_004A3800)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for `wxTopLevelWindow`.
 */
wxTopLevelWindowRootRuntime* wxTopLevelWindowRootRuntime::DeleteWithFlag(
  wxTopLevelWindowRootRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  return reinterpret_cast<wxTopLevelWindowRootRuntime*>(
    wxTopLevelWindowRuntime::DeleteWithFlag(reinterpret_cast<wxTopLevelWindowRuntime*>(object), deleteFlags)
  );
}

/**
 * Address: 0x004A3820 (FUN_004A3820)
 *
 * What it does:
 * Runs the non-deleting top-level-window teardown thunk.
 */
wxTopLevelWindowRootRuntime* wxTopLevelWindowRootRuntime::DestroyWithoutDelete(
  wxTopLevelWindowRootRuntime* const object
) noexcept
{
  return DeleteWithFlag(object, 0);
}

void wxControlContainerRuntime::Initialize(const bool acceptsFocusRecursion) noexcept
{
  mAcceptsFocusRecursion = acceptsFocusRecursion ? 1 : 0;
}

void* wxDialogRuntime::sm_classInfo[1] = {nullptr};

/**
 * Address: 0x004A3860 (FUN_004A3860)
 * Mangled: ??0wxDialogBase@@QAE@@Z
 *
 * What it does:
 * Builds one dialog-base runtime lane, initializes control-container
 * storage, then runs dialog-base init.
 */
wxDialogBaseRuntime::wxDialogBaseRuntime()
  : wxTopLevelWindowRootRuntime()
{
  mControlContainer.Initialize(false);
  InitRuntime();
}

void wxDialogBaseRuntime::InitRuntime() noexcept
{
}

/**
 * Address: 0x004A38C0 (FUN_004A38C0)
 *
 * What it does:
 * Runs non-deleting teardown for dialog-base runtime lanes.
 */
wxDialogBaseRuntime* wxDialogBaseRuntime::DestroyWithoutDelete(wxDialogBaseRuntime* const object) noexcept
{
  return reinterpret_cast<wxDialogBaseRuntime*>(
    wxTopLevelWindowRuntime::DeleteWithFlag(reinterpret_cast<wxTopLevelWindowRuntime*>(object), 0)
  );
}

/**
 * Address: 0x004A38D0 (FUN_004A38D0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for dialog-base runtime lanes.
 */
wxDialogBaseRuntime* wxDialogBaseRuntime::DeleteWithFlag(
  wxDialogBaseRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxDialogRuntimeStateByDialog.erase(reinterpret_cast<const wxDialogRuntime*>(object));
  return reinterpret_cast<wxDialogBaseRuntime*>(
    wxTopLevelWindowRuntime::DeleteWithFlag(
      reinterpret_cast<wxTopLevelWindowRuntime*>(object),
      deleteFlags
    )
  );
}

/**
 * Address: 0x004A3900 (FUN_004A3900)
 * Mangled: ??0wxDialog@@QAE@PAVwxWindow@@HABVwxString@@ABVwxPoint@@ABVwxSize@@J1@Z
 *
 * What it does:
 * Builds one dialog runtime lane, then applies create/init arguments.
 */
wxDialogRuntime::wxDialogRuntime(
  void* const parentWindow,
  const std::int32_t windowId,
  const wxStringRuntime& title,
  const wxPoint& position,
  const wxSize& size,
  const long style,
  const wxStringRuntime& name
)
  : wxDialogBaseRuntime()
{
  WxDialogRuntimeState& state = EnsureWxDialogRuntimeState(this);
  state.parentWindow = parentWindow;
  state.windowId = windowId;
  state.position = position;
  state.size = size;
  state.style = style;
  state.title.assign(title.c_str());
  state.name.assign(name.c_str());
}

/**
 * Address: 0x004A3970 (FUN_004A3970)
 * Mangled: ?GetClassInfo@wxDialog@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for dialog runtime RTTI checks.
 */
void* wxDialogRuntime::GetClassInfo() const
{
  return sm_classInfo;
}

/**
 * Address: 0x004A3980 (FUN_004A3980)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for dialog runtime lanes.
 */
wxDialogRuntime* wxDialogRuntime::DeleteWithFlag(wxDialogRuntime* const object, const std::uint8_t deleteFlags) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxDialogRuntimeStateByDialog.erase(object);
  return reinterpret_cast<wxDialogRuntime*>(
    wxDialogBaseRuntime::DeleteWithFlag(reinterpret_cast<wxDialogBaseRuntime*>(object), deleteFlags)
  );
}

/**
 * Address: 0x004A39A0 (FUN_004A39A0)
 *
 * What it does:
 * Clears this item-id to the null value.
 */
void wxTreeItemIdRuntime::Reset() noexcept
{
  mNode = nullptr;
}

/**
 * Address: 0x004A39B0 (FUN_004A39B0)
 *
 * What it does:
 * Reports whether this item-id currently references a valid node.
 */
bool wxTreeItemIdRuntime::IsValid() const noexcept
{
  return mNode != nullptr;
}

/**
 * Address: 0x004A39C0 (FUN_004A39C0)
 *
 * What it does:
 * Constructs one tree-item payload lane with null item data.
 */
wxTreeItemDataRuntime::wxTreeItemDataRuntime()
  : wxClientDataRuntime()
{
  mPayload = nullptr;
}

/**
 * Address: 0x004A39F0 (FUN_004A39F0)
 *
 * What it does:
 * Rebinds this object to the `wxClientData` base vtable lane.
 */
void wxTreeItemDataRuntime::ResetClientDataBaseVTable() noexcept
{
  ResetRuntimeVTable();
}

/**
 * Address: 0x004A39D0 (FUN_004A39D0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-item payload lanes.
 */
wxTreeItemDataRuntime* wxTreeItemDataRuntime::DeleteWithFlag(
  wxTreeItemDataRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->ResetClientDataBaseVTable();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A3A00 (FUN_004A3A00)
 *
 * What it does:
 * Copies the primary tree-item-id lane into `outItem`.
 */
void wxTreeEventRuntime::GetItem(wxTreeItemIdRuntime* const outItem) const noexcept
{
  if (outItem != nullptr) {
    *outItem = mItem;
  }
}

/**
 * Address: 0x004A3A10 (FUN_004A3A10)
 *
 * What it does:
 * Returns the label storage lane for this tree event.
 */
wxStringRuntime* wxTreeEventRuntime::GetLabelStorage() noexcept
{
  return &mLabel;
}

/**
 * Address: 0x004A3A20 (FUN_004A3A20)
 *
 * What it does:
 * Returns the edit-cancelled flag lane for this tree event.
 */
bool wxTreeEventRuntime::IsEditCancelled() const noexcept
{
  return mEditCancelled != 0;
}

/**
 * Address: 0x004A3A30 (FUN_004A3A30)
 *
 * What it does:
 * Initializes one tree-list column descriptor from title/width/align and
 * owner lane arguments.
 */
wxTreeListColumnInfoRuntime::wxTreeListColumnInfoRuntime(
  const wxStringRuntime& title,
  const std::int32_t width,
  void* const ownerTreeControl,
  const std::uint8_t shown,
  const std::uint8_t alignment,
  const std::int32_t userData
)
{
  mRefData = nullptr;
  mText = wxStringRuntime::Borrow(L"");
  mShown = shown;
  mAlignment = alignment;
  mUserData = userData;
  mText = title;
  mWidth = width;
  mImageIndex = -1;
  mOwnerTreeControl = ownerTreeControl;
}

/**
 * Address: 0x004A3AC0 (FUN_004A3AC0)
 *
 * What it does:
 * Runs non-deleting teardown for one tree-list column descriptor lane.
 */
void wxTreeListColumnInfoRuntime::DestroyWithoutDelete() noexcept
{
  mRefData = nullptr;
  mOwnerTreeControl = nullptr;
}

/**
 * Address: 0x004A3B30 (FUN_004A3B30)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-list column descriptors.
 */
wxTreeListColumnInfoRuntime* wxTreeListColumnInfoRuntime::DeleteWithFlag(
  wxTreeListColumnInfoRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->DestroyWithoutDelete();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

void* wxTreeListCtrlRuntime::sm_classInfo[1] = {nullptr};

/**
 * Address: 0x004A3B50 (FUN_004A3B50)
 * Mangled: ??0wxTreeListCtrl@@QAE@PAVwxWindow@@HABVwxPoint@@ABVwxSize@@JABVwxValidator@@ABVwxString@@@Z
 *
 * What it does:
 * Initializes one tree-list control runtime lane with parent/style/name
 * creation arguments.
 */
wxTreeListCtrlRuntime::wxTreeListCtrlRuntime(
  wxWindowBase* const parentWindow,
  const std::int32_t windowId,
  const wxPoint& position,
  const wxSize& size,
  const long style,
  const wxStringRuntime& name
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  state.parentWindow = parentWindow;
  state.windowId = windowId;
  state.position = position;
  state.size = size;
  state.style = style;
  state.name.assign(name.c_str());
}

/**
 * Address: 0x004A3BD0 (FUN_004A3BD0)
 *
 * What it does:
 * Runs non-deleting teardown for one tree-list control runtime lane.
 */
wxTreeListCtrlRuntime* wxTreeListCtrlRuntime::DestroyWithoutDelete(wxTreeListCtrlRuntime* const object) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxTreeListRuntimeStateByControl.erase(object);
  return object;
}

/**
 * Address: 0x004A3BE0 (FUN_004A3BE0)
 * Mangled: ?AddColumn@wxTreeListCtrl@@QAEXABVwxString@@I_NW4wxTreeListColumnAlign@@@Z
 *
 * What it does:
 * Appends one tree-list column descriptor to this control.
 */
void wxTreeListCtrlRuntime::AddColumn(
  const wxStringRuntime& title,
  const std::uint32_t width,
  const bool shown,
  const std::uint8_t alignment
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  state.columns.emplace_back(
    title,
    static_cast<std::int32_t>(width),
    this,
    shown ? 1u : 0u,
    alignment,
    0
  );
}

/**
 * Address: 0x004A3C50 (FUN_004A3C50)
 * Mangled: ?GetWindowStyleFlag@wxTreeListCtrl@@UBEJXZ
 *
 * What it does:
 * Returns the cached window-style flags for this tree-list control.
 */
long wxTreeListCtrlRuntime::GetWindowStyleFlag() const
{
  const WxTreeListRuntimeState* const state = FindWxTreeListRuntimeState(this);
  return state != nullptr ? state->style : 0;
}

/**
 * Address: 0x004A3C70 (FUN_004A3C70)
 * Mangled: ?GetClassInfo@wxTreeListCtrl@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for tree-list runtime RTTI checks.
 */
void* wxTreeListCtrlRuntime::GetClassInfo() const
{
  return sm_classInfo;
}

/**
 * Address: 0x004A3C80 (FUN_004A3C80)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-list control runtime
 * lanes.
 */
wxTreeListCtrlRuntime* wxTreeListCtrlRuntime::DeleteWithFlag(
  wxTreeListCtrlRuntime* const object,
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

wxTreeItemIdRuntime wxTreeListCtrlRuntime::AddRoot(const wxStringRuntime& text)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  wxTreeItemIdRuntime item{};
  const msvc8::string rootText = text.ToUtf8();
  state.rootNode = AllocateTreeListNode(state, nullptr, rootText);
  item.mNode = state.rootNode;
  return item;
}

wxTreeItemIdRuntime wxTreeListCtrlRuntime::AppendItem(
  const wxTreeItemIdRuntime& parentItem,
  const wxStringRuntime& text
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  wxTreeItemIdRuntime item{};

  WxTreeListNodeRuntimeState* const parentNode = ResolveTreeListNode(parentItem);
  if (parentNode == nullptr) {
    return AddRoot(text);
  }

  const msvc8::string nodeText = text.ToUtf8();
  item.mNode = AllocateTreeListNode(state, parentNode, nodeText);
  return item;
}

void wxTreeListCtrlRuntime::Expand(const wxTreeItemIdRuntime& item) noexcept
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->isExpanded = true;
}

void wxTreeListCtrlRuntime::Collapse(const wxTreeItemIdRuntime& item) noexcept
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->isExpanded = false;
}

bool wxTreeListCtrlRuntime::IsExpanded(const wxTreeItemIdRuntime& item) const noexcept
{
  const WxTreeListNodeRuntimeState* const node = ResolveTreeListNodeConst(item);
  return node != nullptr && node->isExpanded;
}

bool wxTreeListCtrlRuntime::HasChildren(const wxTreeItemIdRuntime& item) const noexcept
{
  const WxTreeListNodeRuntimeState* const node = ResolveTreeListNodeConst(item);
  if (node == nullptr) {
    return false;
  }

  return node->hasChildrenFlag || !node->children.empty();
}

void wxTreeListCtrlRuntime::SortChildren(const wxTreeItemIdRuntime& item)
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr || node->children.size() < 2u) {
    return;
  }

  std::stable_sort(
    node->children.begin(),
    node->children.end(),
    [](const WxTreeListNodeRuntimeState* const lhs, const WxTreeListNodeRuntimeState* const rhs) {
      static const msvc8::string kEmptyText{};
      const msvc8::string& lhsText = (lhs != nullptr && !lhs->columnText.empty()) ? lhs->columnText[0] : kEmptyText;
      const msvc8::string& rhsText = (rhs != nullptr && !rhs->columnText.empty()) ? rhs->columnText[0] : kEmptyText;
      return lhsText < rhsText;
    }
  );
}

void wxTreeListCtrlRuntime::SetItemData(const wxTreeItemIdRuntime& item, wxTreeItemDataRuntime* const itemData)
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->itemData = itemData;
}

wxTreeItemDataRuntime* wxTreeListCtrlRuntime::GetItemData(const wxTreeItemIdRuntime& item) const noexcept
{
  const WxTreeListNodeRuntimeState* const node = ResolveTreeListNodeConst(item);
  return node != nullptr ? node->itemData : nullptr;
}

void wxTreeListCtrlRuntime::SetItemHasChildren(const wxTreeItemIdRuntime& item, const bool hasChildren) noexcept
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->hasChildrenFlag = hasChildren;
}

void wxTreeListCtrlRuntime::SetItemText(
  const wxTreeItemIdRuntime& item,
  const std::uint32_t column,
  const wxStringRuntime& text
)
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }

  if (node->columnText.size() <= column) {
    node->columnText.resize(static_cast<std::size_t>(column) + 1u);
  }
  node->columnText[static_cast<std::size_t>(column)] = text.ToUtf8();
}

/**
 * Address: 0x004A37F0 (FUN_004A37F0)
 * Mangled: ?GetClassInfo@wxFrameBase@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the shared class-info lane used by frame/dialog/top-level
 * `GetClassInfo` slot-0 entries.
 */
void** WX_FrameBaseGetClassInfo() noexcept
{
  return wxTopLevelWindowRootRuntime::sm_classInfo;
}

/**
 * Address: 0x0099E8A0 (FUN_0099E8A0)
 *
 * What it does:
 * Runs non-deleting frame-runtime teardown for frame-derived windows.
 */
wxTopLevelWindowRuntime* WX_FrameDestroyWithoutDelete(wxTopLevelWindowRuntime* const frame) noexcept
{
  if (frame == nullptr) {
    return nullptr;
  }

  // Binary path sets the frame "destroyed" bit before delegating to shared
  // frame-base teardown.
  EnsureWxWindowBaseRuntimeState(frame).bitfields |= 0x8u;
  return wxTopLevelWindowRuntime::DeleteWithFlag(frame, 0u);
}

/**
 * Address: 0x0042B770 (FUN_0042B770)
 * Mangled: ?GetClassInfo@wxWindowBase@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxWindowBase runtime RTTI checks.
 */
void* wxWindowBase::GetClassInfo() const
{
  return gWxWindowBaseClassInfoTable;
}

/**
 * Address: 0x0042B830 (FUN_0042B830)
 * Mangled: ?ContainsHWND@wxWindow@@UBE_NK@Z
 *
 * What it does:
 * Base implementation reports the queried native handle as not contained.
 */
bool wxWindowMswRuntime::ContainsHWND(const unsigned long nativeHandle) const
{
  (void)nativeHandle;
  return false;
}

/**
 * Address: 0x0042B840 (FUN_0042B840)
 * Mangled: ?GetClassInfo@wxWindow@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxWindow runtime RTTI checks.
 */
void* wxWindowMswRuntime::GetClassInfo() const
{
  return gWxWindowClassInfoTable;
}

namespace
{
  template <typename TWindow>
  [[nodiscard]] wxWindowMswRuntime* AllocateWxMswWindowRuntime() noexcept
  {
    return new (std::nothrow) TWindow();
  }

  [[nodiscard]] bool EqualsWindowClassName(const wchar_t* const className, const wchar_t* const expected) noexcept
  {
    return className != nullptr && expected != nullptr && ::_wcsicmp(className, expected) == 0;
  }

  [[nodiscard]] wxWindowMswRuntime* CreateButtonRuntimeFromStyle(const signed char styleLane) noexcept
  {
    if (styleLane == 5 || styleLane == 6 || styleLane == 3 || styleLane == 2) {
      return AllocateWxMswWindowRuntime<wxCheckBoxRuntime>();
    }

    if (styleLane == 9 || styleLane == 4) {
      return AllocateWxMswWindowRuntime<wxControlRuntime>();
    }

    if (styleLane >= 0) {
      switch (styleLane) {
        case 11:
        case 0:
        case 1:
        case 7:
          return AllocateWxMswWindowRuntime<wxControlRuntime>();
        default:
          return nullptr;
      }
    }

    return AllocateWxMswWindowRuntime<wxControlRuntime>();
  }

  [[nodiscard]] wxWindowMswRuntime* CreateRuntimeFromClassAndStyle(
    const wchar_t* const className,
    const signed char styleLane
  ) noexcept
  {
    if (EqualsWindowClassName(className, L"BUTTON")) {
      return CreateButtonRuntimeFromStyle(styleLane);
    }

    if (EqualsWindowClassName(className, L"COMBOBOX")) {
      return AllocateWxMswWindowRuntime<wxControlRuntime>();
    }

    if (EqualsWindowClassName(className, L"EDIT")) {
      return AllocateWxMswWindowRuntime<wxTextCtrlRuntime>();
    }

    if (EqualsWindowClassName(className, L"LISTBOX") ||
        EqualsWindowClassName(className, L"SCROLLBAR") ||
        EqualsWindowClassName(className, L"MSCTLS_UPDOWN32") ||
        EqualsWindowClassName(className, L"MSCTLS_TRACKBAR32")) {
      return AllocateWxMswWindowRuntime<wxControlRuntime>();
    }

    if (EqualsWindowClassName(className, L"STATIC")) {
      if (styleLane == 0 || styleLane == 2 || styleLane == 11 || styleLane == 14) {
        return AllocateWxMswWindowRuntime<wxControlRuntime>();
      }
      return nullptr;
    }

    return nullptr;
  }
} // namespace

/**
 * Address: 0x0097D080 (FUN_0097D080)
 * Mangled: ?CreateWindowFromHWND@wxWindow@@UAEPAV1@PAV1@K@Z
 *
 * What it does:
 * Adapts one native Win32 HWND into the closest recovered wx runtime control
 * wrapper and adopts HWND-derived attributes.
 */
void* wxWindowMswRuntime::CreateWindowFromHWND(void* const parent, const unsigned long nativeHandle)
{
  const HWND nativeWindow = reinterpret_cast<HWND>(nativeHandle);
  if (nativeWindow == nullptr) {
    return nullptr;
  }

  wchar_t windowClassName[64] = {};
  const int classNameLength = ::GetClassNameW(
    nativeWindow,
    windowClassName,
    static_cast<int>(sizeof(windowClassName) / sizeof(windowClassName[0]))
  );
  if (classNameLength <= 0) {
    return nullptr;
  }

  const long windowStyle = static_cast<long>(::GetWindowLongW(nativeWindow, GWL_STYLE));
  const signed char styleLane = static_cast<signed char>(windowStyle & 0xFF);
  const std::int32_t windowId = static_cast<std::uint16_t>(::GetDlgCtrlID(nativeWindow));

  wxWindowMswRuntime* const createdWindow = CreateRuntimeFromClassAndStyle(windowClassName, styleLane);
  if (createdWindow == nullptr) {
    return nullptr;
  }

  wxWindowBase* const parentWindow = static_cast<wxWindowBase*>(parent);
  if (parentWindow != nullptr) {
    parentWindow->AddChild(createdWindow);
  }

  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(createdWindow);
  state.windowStyle = windowStyle;
  state.nativeHandle = nativeHandle;
  state.windowId = windowId;
  state.parentWindow = parentWindow;

  createdWindow->AdoptAttributesFromHWND();
  createdWindow->SetupColours();
  return createdWindow;
}

/**
 * Address: 0x004A3830 (FUN_004A3830)
 * Mangled: ?Command@wxControl@@UAEXAAVwxCommandEvent@@@Z
 *
 * What it does:
 * Forwards one command-event dispatch into `ProcessCommand`.
 */
void wxControlRuntime::Command(void* const commandEvent)
{
  ProcessCommand(commandEvent);
}

/**
 * Address: 0x004A3840 (FUN_004A3840)
 * Mangled: ?MSWOnDraw@wxControl@@UAE_NPAPAX@Z
 *
 * What it does:
 * Base implementation reports that no owner-draw handling was performed.
 */
bool wxControlRuntime::MSWOnDraw(void** const drawStruct)
{
  (void)drawStruct;
  return false;
}

/**
 * Address: 0x004A3850 (FUN_004A3850)
 * Mangled: ?MSWOnMeasure@wxControl@@UAE_NPAPAX@Z
 *
 * What it does:
 * Base implementation reports that no owner-measure handling was performed.
 */
bool wxControlRuntime::MSWOnMeasure(void** const measureStruct)
{
  (void)measureStruct;
  return false;
}

/**
 * Address: 0x0042B3E0 (FUN_0042B3E0)
 * Mangled: ?SetTitle@wxWindowBase@@UAEXPBG@Z
 *
 * What it does:
 * Base implementation accepts but ignores title updates.
 */
void wxWindowBase::SetTitle(const wxStringRuntime& title)
{
  (void)title;
}

/**
 * Address: 0x0042B3F0 (FUN_0042B3F0)
 * Mangled: ?GetTitle@wxWindowBase@@UBE?AVwxString@@XZ
 *
 * What it does:
 * Returns an empty runtime wx string for base windows.
 */
wxStringRuntime wxWindowBase::GetTitle() const
{
  return wxStringRuntime::Borrow(L"");
}

/**
 * Address: 0x0042B420 (FUN_0042B420)
 * Mangled: ?SetLabel@wxWindowBase@@UAEXABVwxString@@@Z
 *
 * What it does:
 * Forwards label updates to `SetTitle`.
 */
void wxWindowBase::SetLabel(const wxStringRuntime& label)
{
  SetTitle(label);
}

/**
 * Address: 0x0042B430 (FUN_0042B430)
 * Mangled: ?GetLabel@wxWindowBase@@UBE?AVwxString@@XZ
 *
 * What it does:
 * Forwards label reads to `GetTitle`.
 */
wxStringRuntime wxWindowBase::GetLabel() const
{
  return GetTitle();
}

/**
 * Address: 0x0042B450 (FUN_0042B450)
 * Mangled: ?SetName@wxWindowBase@@UAEXABVwxString@@@Z
 *
 * What it does:
 * Stores one runtime window-name value.
 */
void wxWindowBase::SetName(const wxStringRuntime& name)
{
  EnsureWxWindowBaseRuntimeState(this).windowName.assign(name.c_str());
}

/**
 * Address: 0x0042B460 (FUN_0042B460)
 * Mangled: ?GetName@wxWindowBase@@UBE?AVwxString@@XZ
 *
 * What it does:
 * Returns the current runtime window-name value.
 */
wxStringRuntime wxWindowBase::GetName() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return wxStringRuntime::Borrow(state != nullptr ? state->windowName.c_str() : L"");
}

/**
 * Address: 0x0042B4F0 (FUN_0042B4F0)
 * Mangled: ?GetMinWidth@wxWindowBase@@UBEHXZ
 */
std::int32_t wxWindowBase::GetMinWidth() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->minWidth : -1;
}

/**
 * Address: 0x0042B500 (FUN_0042B500)
 * Mangled: ?GetMinHeight@wxWindowBase@@UBEHXZ
 */
std::int32_t wxWindowBase::GetMinHeight() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->minHeight : -1;
}

/**
 * Address: 0x0042B510 (FUN_0042B510)
 * Mangled: ?GetMaxSize@wxWindowBase@@UBE?AVwxSize@@XZ
 */
wxSize wxWindowBase::GetMaxSize() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  if (state == nullptr) {
    return wxSize{-1, -1};
  }

  return wxSize{state->maxWidth, state->maxHeight};
}

/**
 * Address: 0x0042B4A0 (FUN_0042B4A0)
 *
 * What it does:
 * Returns client size by forwarding to `DoGetClientSize`.
 */
wxSize wxWindowBase::GetClientSize() const
{
  std::int32_t width = 0;
  std::int32_t height = 0;
  DoGetClientSize(&width, &height);
  return wxSize{width, height};
}

/**
 * Address: 0x0042B4D0 (FUN_0042B4D0)
 *
 * What it does:
 * Returns best size by forwarding to `DoGetBestSize`.
 */
wxSize wxWindowBase::GetBestSize() const
{
  return DoGetBestSize();
}

/**
 * Address: 0x0042B530 (FUN_0042B530)
 * Mangled: ?GetBestVirtualSize@wxWindowBase@@UBE?AVwxSize@@XZ
 */
wxSize wxWindowBase::GetBestVirtualSize() const
{
  std::int32_t clientWidth = 0;
  std::int32_t clientHeight = 0;
  DoGetClientSize(&clientWidth, &clientHeight);

  const wxSize bestSize = DoGetBestSize();
  const std::int32_t width = clientWidth > bestSize.x ? clientWidth : bestSize.x;
  const std::int32_t height = clientHeight > bestSize.y ? clientHeight : bestSize.y;
  return wxSize{width, height};
}

/**
 * Address: 0x0042B5B0 (FUN_0042B5B0)
 * Mangled: ?SetWindowStyleFlag@wxWindowBase@@UAEXJ@Z
 */
void wxWindowBase::SetWindowStyleFlag(const long style)
{
  EnsureWxWindowBaseRuntimeState(this).windowStyle = style;
}

/**
 * Address: 0x0042B5C0 (FUN_0042B5C0)
 * Mangled: ?GetWindowStyleFlag@wxWindowBase@@UBEJXZ
 */
long wxWindowBase::GetWindowStyleFlag() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->windowStyle : 0;
}

/**
 * Address: 0x0042B5F0 (FUN_0042B5F0)
 * Mangled: ?IsRetained@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::IsRetained() const
{
  return ((static_cast<unsigned long>(GetWindowStyleFlag()) >> 17) & 1u) != 0u;
}

/**
 * Address: 0x0042B600 (FUN_0042B600)
 * Mangled: ?SetExtraStyle@wxWindowBase@@UAEXJ@Z
 */
void wxWindowBase::SetExtraStyle(const long style)
{
  EnsureWxWindowBaseRuntimeState(this).extraStyle = style;
}

/**
 * Address: 0x0042B610 (FUN_0042B610)
 * Mangled: ?SetThemeEnabled@wxWindowBase@@UAEX_N@Z
 */
void wxWindowBase::SetThemeEnabled(const bool enabled)
{
  EnsureWxWindowBaseRuntimeState(this).themeEnabled = enabled;
}

/**
 * Address: 0x0042B620 (FUN_0042B620)
 * Mangled: ?GetThemeEnabled@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::GetThemeEnabled() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr && state->themeEnabled;
}

/**
 * Address: 0x0042B630 (FUN_0042B630)
 * Mangled: ?SetFocusFromKbd@wxWindowBase@@UAEXXZ
 */
void wxWindowBase::SetFocusFromKbd()
{
  SetFocus();
}

/**
 * Address: 0x0042B640 (FUN_0042B640)
 * Mangled: ?AcceptsFocus@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::AcceptsFocus() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  if (state == nullptr) {
    return false;
  }

  const std::uint8_t bitfields = state->bitfields;
  return (bitfields & 0x2u) != 0 && (bitfields & 0x4u) != 0;
}

/**
 * Address: 0x0042B660 (FUN_0042B660)
 * Mangled: ?AcceptsFocusFromKeyboard@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::AcceptsFocusFromKeyboard() const
{
  return AcceptsFocus();
}

/**
 * Address: 0x0042B670 (FUN_0042B670)
 * Mangled: ?GetDefaultItem@wxWindowBase@@UBEPAVwxWindow@@XZ
 */
void* wxWindowBase::GetDefaultItem() const
{
  return nullptr;
}

/**
 * Address: 0x0042B680 (FUN_0042B680)
 * Mangled: ?SetDefaultItem@wxWindowBase@@UAEPAVwxWindow@@PAV2@@Z
 */
void* wxWindowBase::SetDefaultItem(void* const defaultItem)
{
  (void)defaultItem;
  return nullptr;
}

/**
 * Address: 0x0042B690 (FUN_0042B690)
 * Mangled: ?SetTmpDefaultItem@wxWindowBase@@UAEXPAVwxWindow@@@Z
 */
void wxWindowBase::SetTmpDefaultItem(void* const defaultItem)
{
  (void)defaultItem;
}

/**
 * Address: 0x0042B6E0 (FUN_0042B6E0)
 * Mangled: ?HasCapture@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::HasCapture() const
{
  return this == GetCapture();
}

wxWindowBase* wxWindowBase::GetCapture()
{
  return gCapturedWindow;
}

/**
 * Address: 0x0042B700 (FUN_0042B700)
 */
void wxWindowBase::Update()
{
}

/**
 * Address: 0x0042B710 (FUN_0042B710)
 */
void wxWindowBase::Freeze()
{
}

/**
 * Address: 0x0042B720 (FUN_0042B720)
 */
void wxWindowBase::Thaw()
{
}

/**
 * Address: 0x0042B730 (FUN_0042B730)
 * Mangled: ?PrepareDC@wxWindowBase@@UAEXAAVwxDC@@@Z
 */
void wxWindowBase::PrepareDC(void* const deviceContext)
{
  (void)deviceContext;
}

/**
 * Address: 0x0042B740 (FUN_0042B740)
 */
bool wxWindowBase::ScrollLines(const std::int32_t lines)
{
  (void)lines;
  return false;
}

/**
 * Address: 0x0042B750 (FUN_0042B750)
 */
bool wxWindowBase::ScrollPages(const std::int32_t pages)
{
  (void)pages;
  return false;
}

void wxWindowBase::SetDropTarget(void* const dropTarget)
{
  EnsureWxWindowBaseRuntimeState(this).dropTarget = dropTarget;
}

/**
 * Address: 0x0042B760 (FUN_0042B760)
 * Mangled: ?GetDropTarget@wxWindowBase@@UBEPAVwxDropTarget@@XZ
 */
void* wxWindowBase::GetDropTarget() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->dropTarget : nullptr;
}

msvc8::vector<moho::ManagedWindowSlot> moho::managedWindows{};
msvc8::vector<moho::ManagedWindowSlot> moho::managedFrames{};
wxWindowBase* moho::sMainWindow = nullptr;
moho::WRenViewport* moho::ren_Viewport = nullptr;

moho::wxDCRuntime::wxDCRuntime(wxWindowBase* const ownerWindow) noexcept : mOwnerWindow(ownerWindow)
{
}

void moho::wxDCRuntime::SetBrush(const void* const brushToken) noexcept
{
  mActiveBrush = brushToken;
}

void moho::wxDCRuntime::DoGetSize(std::int32_t* const outWidth, std::int32_t* const outHeight) const noexcept
{
  if (mOwnerWindow != nullptr) {
    mOwnerWindow->DoGetSize(outWidth, outHeight);
    return;
  }

  if (outWidth != nullptr) {
    *outWidth = 0;
  }
  if (outHeight != nullptr) {
    *outHeight = 0;
  }
}

void moho::wxDCRuntime::DoDrawRectangle(
  const std::int32_t x,
  const std::int32_t y,
  const std::int32_t width,
  const std::int32_t height
) noexcept
{
  (void)x;
  (void)y;
  (void)width;
  (void)height;
  (void)mActiveBrush;
}

moho::wxPaintDCRuntime::wxPaintDCRuntime(wxWindowBase* const ownerWindow) noexcept : wxDCRuntime(ownerWindow)
{
}

moho::wxPaintDCRuntime::~wxPaintDCRuntime() = default;

bool moho::WX_EnsureSplashPngHandler()
{
  if (gSplashPngHandlerInitialized) {
    return true;
  }

  // Source-only runtime tracks registration state without importing wx handlers.
  gSplashPngHandlerInitialized = true;
  return true;
}

moho::SplashScreenRuntime* moho::WX_CreateSplashScreen(const char* const filename, const wxSize& size)
{
  if (filename == nullptr || filename[0] == '\0') {
    return nullptr;
  }

  std::error_code pathError;
  std::filesystem::path splashPath(filename);
  if (!splashPath.is_absolute()) {
    splashPath = std::filesystem::absolute(splashPath, pathError);
    if (pathError) {
      return nullptr;
    }
  }

  if (!std::filesystem::exists(splashPath, pathError) || pathError) {
    return nullptr;
  }

  msvc8::string splashPathText;
  splashPathText.assign_owned(splashPath.generic_string());
  return new (std::nothrow) SplashScreenRuntimeImpl(splashPathText, size);
}

void* moho::WD3DViewport::sm_eventTable[1] = {nullptr};

/**
 * Address: 0x00430980 (FUN_00430980)
 * Mangled:
 * ??0WD3DViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxPoint@@ABVwxSize@@@Z
 *
 * What it does:
 * Converts the startup title lane to wide text for wx window creation flow,
 * binds parent ownership, and clears retained D3D device reference storage.
 */
moho::WD3DViewport::WD3DViewport(
  wxWindowBase* const parentWindow,
  const char* const title,
  const wxPoint& position,
  const wxSize& size
)
{
  (void)position;
  (void)size;

  const std::wstring wideTitle = gpg::STR_Utf8ToWide(title != nullptr ? title : "");
  (void)wideTitle;

  std::memset(mUnknown04To1C, 0, sizeof(mUnknown04To1C));
  mEnabled = 0;
  std::memset(mUnknown1ETo2B, 0, sizeof(mUnknown1ETo2B));
  m_parent = parentWindow;
  mD3DDevice = nullptr;
}

/**
 * Address: 0x0042BA90 (FUN_0042BA90)
 * Mangled: ??1WD3DViewport@Moho@@UAE@XZ
 *
 * What it does:
 * Releases one held D3D-device reference before base window teardown.
 */
moho::WD3DViewport::~WD3DViewport()
{
  ReleaseD3DDeviceRef(mD3DDevice);
  mD3DDevice = nullptr;
}

/**
 * Address: 0x0042BAF0 (FUN_0042BAF0)
 */
void moho::WD3DViewport::D3DWindowOnDeviceInit()
{
}

/**
 * Address: 0x0042BB00 (FUN_0042BB00)
 */
void moho::WD3DViewport::D3DWindowOnDeviceRender()
{
}

/**
 * Address: 0x0042BB10 (FUN_0042BB10)
 */
void moho::WD3DViewport::D3DWindowOnDeviceExit()
{
}

/**
 * Address: 0x0042BB20 (FUN_0042BB20)
 */
void moho::WD3DViewport::RenderPreviewImage()
{
}

/**
 * Address: 0x0042BB30 (FUN_0042BB30)
 */
moho::WPreviewImageRuntime moho::WD3DViewport::GetPreviewImage() const
{
  return {};
}

/**
 * Address: 0x0042BB50 (FUN_0042BB50)
 */
void* moho::WD3DViewport::GetPrimBatcher() const
{
  return nullptr;
}

/**
 * Address: 0x00430970 (FUN_00430970)
 * Mangled: ?GetEventTable@WD3DViewport@Moho@@MBEPBUwxEventTable@@XZ
 *
 * What it does:
 * Returns the static event-table lane for this viewport runtime type.
 */
const void* moho::WD3DViewport::GetEventTable() const
{
  return sm_eventTable;
}

namespace
{
  constexpr std::uintptr_t kWxBlackBrushToken = 1u;
  constexpr std::uintptr_t kWxNullBrushToken = 0u;
  constexpr std::uint16_t kClientHitTestCode = 1u;

  void DrawBackgroundFill(moho::wxDCRuntime& deviceContext)
  {
    std::int32_t width = 0;
    std::int32_t height = 0;

    deviceContext.SetBrush(reinterpret_cast<const void*>(kWxBlackBrushToken));
    deviceContext.DoGetSize(&width, &height);
    deviceContext.DoDrawRectangle(0, 0, width, height);
    deviceContext.SetBrush(reinterpret_cast<const void*>(kWxNullBrushToken));
  }

  struct [[maybe_unused]] WD3DViewportPaintCallbackFrame
  {
    std::uint8_t mUnknown00To1F[0x20]{};
    moho::wxDCRuntime* mDeviceContext = nullptr;
  };

  static_assert(
    offsetof(WD3DViewportPaintCallbackFrame, mDeviceContext) == 0x20,
    "WD3DViewportPaintCallbackFrame::mDeviceContext offset must be 0x20"
  );

  /**
   * Address: 0x00430B70 (FUN_00430B70)
   *
   * What it does:
   * Draws viewport background into the supplied paint DC when D3D device is
   * missing or still in background-fallback mode.
   */
  [[maybe_unused]] void WD3DViewportPaintBackgroundFallback(WD3DViewportPaintCallbackFrame* const callbackFrame)
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (callbackFrame == nullptr || callbackFrame->mDeviceContext == nullptr) {
      return;
    }

    if (device == nullptr || device->ShouldDrawViewportBackground()) {
      DrawBackgroundFill(*callbackFrame->mDeviceContext);
    }
  }
} // namespace

/**
 * Address: 0x00430A60 (FUN_00430A60)
 * Mangled: ?DrawBackgroundImage@WD3DViewport@Moho@@AAEXAAVwxDC@@@Z
 *
 * What it does:
 * Fills the viewport paint DC with a solid black rectangle.
 */
void moho::WD3DViewport::DrawBackgroundImage(wxDCRuntime& deviceContext)
{
  DrawBackgroundFill(deviceContext);
}

/**
 * Address: 0x00430AC0 (FUN_00430AC0)
 * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
 *
 * What it does:
 * Builds one paint DC, then renders through active D3D device when ready or
 * draws fallback background.
 */
void moho::WD3DViewport::OnPaint(wxPaintEventRuntime& paintEvent)
{
  (void)paintEvent;
  wxPaintDCRuntime paintDc(this);

  CD3DDevice* const device = D3D_GetDevice();
  if (gpg::gal::Device::IsReady() && device != nullptr) {
    ReleaseD3DDeviceRef(mD3DDevice);
    mD3DDevice = nullptr;
    device->Paint();
    return;
  }

  DrawBackgroundImage(paintDc);
}

/**
 * Address: 0x00430B90 (FUN_00430B90)
 * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
 *
 * What it does:
 * Handles cursor ownership handoff between wx and D3D, then delegates
 * unhandled messages to base window dispatch.
 */
long moho::WD3DViewport::MSWWindowProc(
  const unsigned int message, const unsigned int wParam, const long lParam
)
{
  CD3DDevice* const device = D3D_GetDevice();
  if (device != nullptr) {
    const bool setCursorMessage = message == WM_SETCURSOR;
    const bool clientHit = static_cast<std::uint16_t>(lParam & 0xFFFF) == kClientHitTestCode;

    if (d3d_WindowsCursor) {
      if (setCursorMessage && clientHit && device->IsCursorPixelSourceReady()) {
        gpg::gal::Device::InitCursor();
        (void)device->ShowCursor(device->IsCursorShowing());
        return 1;
      }
    } else if (setCursorMessage && clientHit && (device->IsCursorPixelSourceReady() || !device->IsCursorShowing())) {
      ::SetCursor(nullptr);
      gpg::gal::Device::InitCursor();
      (void)device->ShowCursor(device->IsCursorShowing());
      return 1;
    }
  }

  return WRenViewport::MSWWindowProc(message, wParam, lParam);
}

/**
 * Address: 0x0042BB60 (FUN_0042BB60)
 *
 * What it does:
 * Deleting-dtor thunk lane for `WD3DViewport`.
 */
static moho::WD3DViewport* DeleteWD3DViewportThunk(
  moho::WD3DViewport* const viewport, const std::uint8_t deleteFlags
)
{
  if (viewport == nullptr) {
    return nullptr;
  }

  viewport->~WD3DViewport();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(viewport);
  }
  return viewport;
}

namespace
{
  constexpr std::size_t kMaxCommittedLogLines = 10000;
  constexpr std::uint32_t kCustomFilterCategoryBit = 1u << 4;
  constexpr std::uint32_t kWarningCategoryValue = 2u;
  constexpr std::uint32_t kErrorCategoryValue = 3u;
  constexpr std::size_t kReplayIndentWidth = 4u;
  constexpr const char* kLogCategoryPreferenceKeys[] = {
    "Options.Log.Debug",
    "Options.Log.Info",
    "Options.Log.Warn",
    "Options.Log.Error",
    "Options.Log.Custom",
  };
  constexpr bool kLogCategoryPreferenceDefaults[] = {
    false,
    true,
    true,
    true,
    true,
  };
  constexpr const char* kLogFilterPreferenceKey = "Options.Log.Filter";
  constexpr const char* kLogFilterPreferenceDefault = "*DEBUG:";
  constexpr const char* kLogWindowXPreferenceKey = "Windows.Log.x";
  constexpr const char* kLogWindowYPreferenceKey = "Windows.Log.y";
  constexpr const char* kLogWindowWidthPreferenceKey = "Windows.Log.width";
  constexpr const char* kLogWindowHeightPreferenceKey = "Windows.Log.height";
  constexpr std::int32_t kLogWindowGeometryFallback = -1;
  constexpr std::int32_t kLogWindowSetSizeFlags = 3;

  [[nodiscard]] wxTextAttrRuntime BuildTextStyleFromRgb(
    const std::uint8_t red, const std::uint8_t green, const std::uint8_t blue
  ) noexcept
  {
    return wxTextAttrRuntime(
      wxColourRuntime::FromRgb(red, green, blue),
      wxColourRuntime::Null(),
      wxFontRuntime::Null()
    );
  }

  [[nodiscard]] wxTextAttrRuntime DefaultTextStyleForCategory(const std::uint32_t category) noexcept
  {
    switch (category) {
      case 0u:
        return BuildTextStyleFromRgb(0x80, 0x80, 0x80);
      case kWarningCategoryValue:
        return BuildTextStyleFromRgb(0xF7, 0xA1, 0x00);
      case kErrorCategoryValue:
        return BuildTextStyleFromRgb(0xFF, 0x00, 0x00);
      default:
        return BuildTextStyleFromRgb(0x00, 0x00, 0x00);
    }
  }
}

[[nodiscard]] const wchar_t* wxStringRuntime::c_str() const noexcept
{
  return m_pchData != nullptr ? m_pchData : L"";
}

msvc8::string wxStringRuntime::ToUtf8() const
{
  return gpg::STR_WideToUtf8(c_str());
}

msvc8::string wxStringRuntime::ToUtf8Lower() const
{
  const msvc8::string value = ToUtf8();
  return gpg::STR_ToLower(value.c_str());
}

wxStringRuntime wxStringRuntime::Borrow(const wchar_t* const text) noexcept
{
  wxStringRuntime runtime{};
  runtime.m_pchData = const_cast<wchar_t*>(text != nullptr ? text : L"");
  return runtime;
}

/**
 * Address: 0x0042B870 (FUN_0042B870)
 * Mangled: ??0wxImageHandler@@QAE@@Z
 *
 * What it does:
 * Initializes name/extension/mime string lanes and sets type to invalid.
 */
wxImageHandlerRuntime::wxImageHandlerRuntime()
{
  mRefData = nullptr;
  mName = wxStringRuntime::Borrow(L"");
  mExtension = wxStringRuntime::Borrow(L"");
  mMime = wxStringRuntime::Borrow(L"");
  mType = 0;
}

void wxImageHandlerRuntime::SetDescriptor(
  const wchar_t* const name,
  const wchar_t* const extension,
  const wchar_t* const mimeType,
  const std::int32_t bitmapType
) noexcept
{
  mName = wxStringRuntime::Borrow(name != nullptr ? name : L"");
  mExtension = wxStringRuntime::Borrow(extension != nullptr ? extension : L"");
  mMime = wxStringRuntime::Borrow(mimeType != nullptr ? mimeType : L"");
  mType = bitmapType;
}

/**
 * Address: 0x0042B8F0 (FUN_0042B8F0)
 * Mangled: ?GetClassInfo@wxImageHandler@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxImageHandler runtime RTTI checks.
 */
void* wxImageHandlerRuntime::GetClassInfo() const
{
  return gWxImageHandlerClassInfoTable;
}

void wxImageHandlerRuntime::ReleaseSharedWxString(wxStringRuntime& value) noexcept
{
  // Runtime wrappers keep wxString lanes as borrowed views; dropping one lane
  // is represented by clearing the pointer.
  value.m_pchData = nullptr;
}

/**
 * Address: 0x0042B920 (FUN_0042B920)
 *
 * What it does:
 * Releases runtime string lanes and clears shared ref-data ownership.
 */
wxImageHandlerRuntime::~wxImageHandlerRuntime()
{
  ReleaseSharedWxString(mMime);
  ReleaseSharedWxString(mExtension);
  ReleaseSharedWxString(mName);
  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(this));
}

/**
 * Address: 0x0042B9E0 (FUN_0042B9E0)
 * Mangled: ??0wxPNGHandler@@QAE@XZ
 *
 * What it does:
 * Initializes the PNG handler descriptor (name, extension, mime, bitmap type).
 */
wxPngHandlerRuntime::wxPngHandlerRuntime()
{
  // wxBitmapType::wxBITMAP_TYPE_PNG in this runtime lane.
  constexpr std::int32_t kBitmapTypePng = 15;
  SetDescriptor(L"PNG file", L"png", L"image/png", kBitmapTypePng);
}

/**
 * Address: 0x0042BA50 (FUN_0042BA50)
 * Mangled: ?GetClassInfo@wxPNGHandler@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxPNGHandler runtime RTTI checks.
 */
void* wxPngHandlerRuntime::GetClassInfo() const
{
  return gWxPngHandlerClassInfoTable;
}

/**
 * Address: 0x0042BA60 (FUN_0042BA60)
 *
 * What it does:
 * Deleting-dtor thunk lane for `wxPNGHandler`; no extra teardown beyond base.
 */
wxPngHandlerRuntime::~wxPngHandlerRuntime() = default;

wxColourRuntime wxColourRuntime::FromRgb(
  const std::uint8_t red, const std::uint8_t green, const std::uint8_t blue
) noexcept
{
  wxColourRuntime color{};
  color.mStorage[0] = red;
  color.mStorage[1] = green;
  color.mStorage[2] = blue;
  color.mStorage[3] = 0xFF;
  return color;
}

const wxColourRuntime& wxColourRuntime::Null() noexcept
{
  static const wxColourRuntime kNullColour{};
  return kNullColour;
}

const wxFontRuntime& wxFontRuntime::Null() noexcept
{
  static const wxFontRuntime kNullFont{};
  return kNullFont;
}

/**
 * Address: 0x004F36A0 (FUN_004F36A0)
 *
 * What it does:
 * Initializes one text-style payload from explicit foreground/background/font
 * runtime lanes.
 */
wxTextAttrRuntime::wxTextAttrRuntime(
  const wxColourRuntime& foreground,
  const wxColourRuntime& background,
  const wxFontRuntime& font
)
  : mForegroundColour(foreground)
  , mBackgroundColour(background)
  , mFont(font)
{
}

/**
 * Address: 0x004F63B0 (FUN_004F63B0)
 *
 * What it does:
 * Destroys text-style subobjects in reverse order.
 */
wxTextAttrRuntime::~wxTextAttrRuntime() = default;

msvc8::string wxTextCtrlRuntime::GetValueUtf8() const
{
  return GetValue().ToUtf8();
}

msvc8::string wxTextCtrlRuntime::GetValueUtf8Lower() const
{
  return GetValue().ToUtf8Lower();
}

void wxTextCtrlRuntime::SetValueUtf8(const msvc8::string& value)
{
  const std::wstring wideValue = gpg::STR_Utf8ToWide(value.c_str());
  SetValue(wxStringRuntime::Borrow(wideValue.c_str()));
}

void wxTextCtrlRuntime::AppendUtf8(const msvc8::string& text)
{
  const std::wstring wideText = gpg::STR_Utf8ToWide(text.c_str());
  AppendText(wxStringRuntime::Borrow(wideText.c_str()));
}

void wxTextCtrlRuntime::AppendWide(const std::wstring& text)
{
  AppendText(wxStringRuntime::Borrow(text.c_str()));
}

void wxTextCtrlRuntime::ScrollToLastPosition()
{
  ShowPosition(GetLastPosition());
}

/**
 * Address: 0x004F73B0 (FUN_004F73B0)
 *
 * What it does:
 * Constructs one wide stream/buffer helper used by log-window text formatting.
 */
moho::WWinLogTextBuilder::WWinLogTextBuilder() = default;

/**
 * Address: 0x004F74D0 (FUN_004F74D0)
 *
 * What it does:
 * Finalizes stream state and returns the accumulated wide text.
 */
const std::wstring& moho::WWinLogTextBuilder::Finalize() const noexcept
{
  return mText;
}

void moho::WWinLogTextBuilder::SetFieldWidth(const std::size_t width) noexcept
{
  mFieldWidth = width;
}

void moho::WWinLogTextBuilder::Clear() noexcept
{
  mText.clear();
  mFieldWidth = 0;
  mFillCodePoint = L' ';
  mLeftAlign = false;
}

/**
 * Address: 0x004F98F0 (FUN_004F98F0)
 *
 * What it does:
 * Emits one code-point with optional field-width padding and clears transient
 * width state.
 */
void moho::WWinLogTextBuilder::WriteCodePoint(const wchar_t codePoint)
{
  const std::wstring oneCodePoint(1, codePoint);
  WriteWideText(oneCodePoint);
}

/**
 * Address: 0x004F9B80 (FUN_004F9B80)
 *
 * What it does:
 * Emits one wide string with optional field-width padding and clears transient
 * width state.
 */
void moho::WWinLogTextBuilder::WriteWideText(const std::wstring& text)
{
  const std::size_t paddingCount = mFieldWidth > text.size() ? mFieldWidth - text.size() : 0;
  if (!mLeftAlign && paddingCount != 0) {
    mText.append(paddingCount, mFillCodePoint);
  }

  mText += text;

  if (mLeftAlign && paddingCount != 0) {
    mText.append(paddingCount, mFillCodePoint);
  }

  mFieldWidth = 0;
}

/**
 * Address: 0x004F9DF0 (FUN_004F9DF0)
 *
 * What it does:
 * Emits one wide-string literal with width/padding behavior.
 */
void moho::WWinLogTextBuilder::WriteWideLiteral(const wchar_t* const text)
{
  WriteWideText(text != nullptr ? std::wstring(text) : std::wstring{});
}

/**
 * Address: 0x004FA000 (FUN_004FA000)
 *
 * What it does:
 * Emits one UTF-8 fragment by widening it then appending with width behavior.
 */
void moho::WWinLogTextBuilder::WriteUtf8Text(const msvc8::string& text)
{
  WriteWideText(gpg::STR_Utf8ToWide(text.c_str()));
}

/**
 * Address: 0x004FA2C0 (FUN_004FA2C0)
 *
 * What it does:
 * Emits one decoded wide code-point.
 */
void moho::WWinLogTextBuilder::WriteDecodedCodePoint(const wchar_t codePoint)
{
  WriteCodePoint(codePoint);
}

/**
 * Address: 0x004F5AB0 (FUN_004F5AB0)
 *
 * What it does:
 * Emits one run of space code-points.
 */
void moho::WWinLogTextBuilder::WriteSpaces(std::size_t count)
{
  while (count > 0) {
    WriteCodePoint(L' ');
    --count;
  }
}

bool moho::CWinLogLine::IsReplayEntry() const noexcept
{
  return isReplayEntry != 0u;
}

bool moho::CWinLogLine::IsMessageEntry() const noexcept
{
  return !IsReplayEntry();
}

const wchar_t* moho::CWinLogLine::SeverityPrefix() const noexcept
{
  switch (categoryMask) {
    case 0u:
      return L"DEBUG: ";
    case kWarningCategoryValue:
      return L"WARNING: ";
    case kErrorCategoryValue:
      return L"ERROR: ";
    default:
      return L"INFO: ";
  }
}

/**
 * Address: 0x00978FF0 (FUN_00978FF0, ??0wxEvent@@QAE@@Z)
 *
 * What it does:
 * Initializes one wxEvent runtime payload from `(eventId, eventType)` and
 * clears ref/object/timestamp/flag lanes.
 */
wxEventRuntime::wxEventRuntime(const std::int32_t eventId, const std::int32_t eventType)
  : mRefData(nullptr)
  , mEventObject(nullptr)
  , mEventType(eventType)
  , mEventTimestamp(0)
  , mEventId(eventId)
  , mCallbackUserData(nullptr)
  , mSkipped(0)
  , mIsCommandEvent(0)
  , mReserved1E(0)
  , mReserved1F(0)
{
}

/**
 * Address: 0x00979090 (FUN_00979090, ??0wxCommandEvent@@QAE@@Z)
 *
 * What it does:
 * Initializes one wxCommandEvent payload on top of wxEvent runtime state and
 * sets the command-event marker flag.
 */
wxCommandEventRuntime::wxCommandEventRuntime(const std::int32_t commandType, const std::int32_t eventId)
  : wxEventRuntime(eventId, commandType)
  , mCommandString(wxStringRuntime::Borrow(L""))
  , mCommandInt(0)
  , mExtraLong(0)
  , mClientData(nullptr)
  , mClientObject(nullptr)
{
  mIsCommandEvent = 1u;
}

/**
 * Address: 0x006609B0 (FUN_006609B0, ??1wxCommandEvent@@QAE@@Z)
 *
 * What it does:
 * Releases one shared command-string payload and clears wxEvent ref-data
 * ownership via the base unref tail.
 */
wxCommandEventRuntime::~wxCommandEventRuntime()
{
  ReleaseWxStringSharedPayload(mCommandString);
  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(this));
}

/**
 * Address: 0x004F38E0 (FUN_004F38E0)
 *
 * What it does:
 * Returns the static wx class-info lane for this event payload type.
 */
void* moho::CLogAdditionEvent::GetClassInfo() const
{
  return gCLogAdditionEventClassInfoTable;
}

/**
 * Address: 0x004F3850 (FUN_004F3850)
 *
 * What it does:
 * Deleting-dtor entry for this event payload type.
 */
void moho::CLogAdditionEvent::DeleteObject()
{
  delete this;
}

/**
 * Address: 0x004F37F0 (FUN_004F37F0)
 *
 * What it does:
 * Allocates and copy-clones one `CLogAdditionEvent` object.
 */
moho::CLogAdditionEvent* moho::CLogAdditionEvent::Clone() const
{
  return new CLogAdditionEvent(*this);
}

/**
 * Address: 0x004F38F0 (FUN_004F38F0, ??0CWinLogTarget@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes the global log-target owner and auto-registers it with gpg logging.
 */
moho::CWinLogTarget::CWinLogTarget()
  : gpg::LogTarget(true)
{
}

/**
 * Address: 0x004F39B0 (FUN_004F39B0)
 * Mangled deleting-dtor thunk: 0x004F3990 (FUN_004F3990)
 *
 * What it does:
 * Releases pending/committed vectors and tears down base log-target registration.
 */
moho::CWinLogTarget::~CWinLogTarget() = default;

/**
 * Address: 0x004F6F40 (FUN_004F6F40)
 *
 * What it does:
 * Appends one line record into the pending queue.
 */
void moho::CWinLogTarget::AppendPendingLine(const CWinLogLine& line)
{
  mPendingLines.push_back(line);
}

/**
 * Address: 0x004F6F10 (FUN_004F6F10)
 *
 * What it does:
 * Returns committed line count.
 */
std::size_t moho::CWinLogTarget::CommittedLineCount() const
{
  return mCommittedLines.size();
}

const msvc8::vector<moho::CWinLogLine>& moho::CWinLogTarget::CommittedLines() const
{
  return mCommittedLines;
}

/**
 * Address: 0x004F6FD0 (FUN_004F6FD0)
 *
 * What it does:
 * Replaces committed-line storage with a copy of `nextCommittedLines`.
 */
void moho::CWinLogTarget::ReplaceCommittedLines(const msvc8::vector<CWinLogLine>& nextCommittedLines)
{
  mCommittedLines = nextCommittedLines;
}

void moho::CWinLogTarget::SnapshotCommittedLines(msvc8::vector<CWinLogLine>* const outLines)
{
  if (outLines == nullptr) {
    return;
  }

  boost::mutex::scoped_lock scopedLock(lock);
  *outLines = mCommittedLines;
}

void moho::CWinLogTarget::ResetCommittedLinesFromReplayBuffer(const msvc8::vector<msvc8::string>& replayLines)
{
  boost::mutex::scoped_lock scopedLock(lock);

  msvc8::vector<CWinLogLine> rebuiltLines;
  rebuiltLines.reserve(replayLines.size());
  for (std::size_t index = 0; index < replayLines.size(); ++index) {
    CWinLogLine replayLine{};
    replayLine.isReplayEntry = 1;
    replayLine.sequenceIndex = static_cast<std::uint32_t>(index);
    replayLine.categoryMask = 1;
    replayLine.text = replayLines[index];
    rebuiltLines.push_back(replayLine);
  }

  ReplaceCommittedLines(rebuiltLines);
}

/**
 * Address: 0x004F6A50 (FUN_004F6A50)
 *
 * What it does:
 * Merges pending lines into committed history and enforces the 10,000 line cap.
 */
void moho::CWinLogTarget::MergePendingLines()
{
  boost::mutex::scoped_lock scopedLock(lock);

  const std::size_t pendingCount = mPendingLines.size();
  const std::size_t committedCount = mCommittedLines.size();
  if (committedCount + pendingCount > kMaxCommittedLogLines) {
    const std::size_t dropCount = (std::min)(committedCount, pendingCount);
    if (dropCount != 0) {
      mCommittedLines.erase(mCommittedLines.begin(), mCommittedLines.begin() + dropCount);
    }
  }

  for (const CWinLogLine& line : mPendingLines) {
    mCommittedLines.push_back(line);
  }
  mPendingLines.clear();
}

/**
 * Address: 0x004F6860 (FUN_004F6860)
 *
 * gpg::LogSeverity level, msvc8::string const &, msvc8::vector<msvc8::string> const &, int
 *
 * What it does:
 * Queues replay/context lines plus the current line into the pending log queue.
 */
void moho::CWinLogTarget::OnMessage(
  const gpg::LogSeverity level,
  const msvc8::string& message,
  const msvc8::vector<msvc8::string>& context,
  const int previousDepth
)
{
  boost::mutex::scoped_lock scopedLock(lock);

  std::size_t replayStart = 0;
  if (previousDepth > 0) {
    replayStart = static_cast<std::size_t>(previousDepth);
  }
  if (replayStart > context.size()) {
    replayStart = context.size();
  }

  const std::uint32_t categoryMask = static_cast<std::uint32_t>(level);
  for (std::size_t index = replayStart; index < context.size(); ++index) {
    CWinLogLine replayLine{};
    replayLine.isReplayEntry = 1;
    replayLine.sequenceIndex = static_cast<std::uint32_t>(index);
    replayLine.categoryMask = categoryMask;
    replayLine.text = context[index];
    AppendPendingLine(replayLine);
  }

  CWinLogLine messageLine{};
  messageLine.isReplayEntry = 0;
  messageLine.sequenceIndex = static_cast<std::uint32_t>(context.size());
  messageLine.categoryMask = categoryMask;
  messageLine.text = message;
  AppendPendingLine(messageLine);

  WWinLogWindow* const dialogWindow = dialog;
  scopedLock.unlock();
  if (dialogWindow != nullptr) {
    const CLogAdditionEvent event{};
    dialogWindow->OnTargetPendingLinesChanged(event);
  }
}

/**
 * Address: 0x004F4270 (FUN_004F4270)
 *
 * What it does:
 * Constructs one managed log-window object and seeds control/runtime state
 * lanes used by downstream append/rebuild handlers.
 */
moho::WWinLogWindow::WWinLogWindow()
{
  mIsInitializingControls = 1;
  mEnabledCategoriesMask = 0;
  mFilterText.clear();
  mBufferedLines.clear();
  mFirstVisibleLine = 0;
  RegisterManagedOwnerSlot();
  InitializeFromUserPreferences();
  mIsInitializingControls = 0;
}

void moho::WWinLogWindow::InitializeFromUserPreferences()
{
  IUserPrefs* const preferences = USER_GetPreferences();
  RestoreCategoryStateFromPreferences(preferences);
  RestoreFilterFromPreferences(preferences);
  RestoreGeometryFromPreferences(preferences);
}

void moho::WWinLogWindow::RestoreCategoryStateFromPreferences(IUserPrefs* const preferences)
{
  mEnabledCategoriesMask = 0;

  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    const bool enabled = preferences != nullptr
                           ? preferences->GetBoolean(
                               msvc8::string(kLogCategoryPreferenceKeys[index]),
                               kLogCategoryPreferenceDefaults[index]
                             )
                           : kLogCategoryPreferenceDefaults[index];

    if (enabled) {
      mEnabledCategoriesMask |= (1u << static_cast<std::uint32_t>(index));
    }

    if (checkBoxes[index] != nullptr) {
      checkBoxes[index]->SetValue(enabled);
    }
  }
}

void moho::WWinLogWindow::RestoreFilterFromPreferences(IUserPrefs* const preferences)
{
  const msvc8::string fallback(kLogFilterPreferenceDefault);
  if (preferences != nullptr) {
    mFilterText = preferences->GetString(msvc8::string(kLogFilterPreferenceKey), fallback);
  } else {
    mFilterText = fallback;
  }

  if (mFilterTextControl != nullptr) {
    mFilterTextControl->SetValueUtf8(mFilterText);
  }
}

void moho::WWinLogWindow::RestoreGeometryFromPreferences(IUserPrefs* const preferences)
{
  if (preferences == nullptr) {
    return;
  }

  const std::int32_t height =
    preferences->GetInteger(msvc8::string(kLogWindowHeightPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t width =
    preferences->GetInteger(msvc8::string(kLogWindowWidthPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t y = preferences->GetInteger(msvc8::string(kLogWindowYPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t x = preferences->GetInteger(msvc8::string(kLogWindowXPreferenceKey), kLogWindowGeometryFallback);

  DoSetSize(x, y, width, height, kLogWindowSetSizeFlags);
}

/**
 * Address: 0x004F5380 (FUN_004F5380)
 * Mangled deleting-dtor thunk: 0x004F5360 (FUN_004F5360)
 *
 * What it does:
 * Detaches from the owner log target, clears local storage lanes, and unlinks
 * managed-owner slots.
 */
moho::WWinLogWindow::~WWinLogWindow()
{
  DetachFromTarget();
  mBufferedLines.clear();
  mFilterText.clear();
  ReleaseManagedOwnerSlots();
}

void moho::WWinLogWindow::SetOwnerTarget(CWinLogTarget* const ownerTarget) noexcept
{
  mOwnerTarget = ownerTarget;
}

/**
 * Address: 0x004F6760 (FUN_004F6760)
 *
 * What it does:
 * Clears `mOwnerTarget->dialog` under the target lock.
 */
void moho::WWinLogWindow::DetachFromTarget()
{
  if (mOwnerTarget == nullptr) {
    return;
  }

  boost::mutex::scoped_lock scopedLock(mOwnerTarget->lock);
  mOwnerTarget->dialog = nullptr;
}

std::array<wxCheckBoxRuntime*, 5> moho::WWinLogWindow::CategoryCheckBoxes() noexcept
{
  return {
    mDebugCategoryCheckBox,
    mInfoCategoryCheckBox,
    mWarnCategoryCheckBox,
    mErrorCategoryCheckBox,
    mCustomCategoryCheckBox,
  };
}

std::array<const wxCheckBoxRuntime*, 5> moho::WWinLogWindow::CategoryCheckBoxes() const noexcept
{
  return {
    mDebugCategoryCheckBox,
    mInfoCategoryCheckBox,
    mWarnCategoryCheckBox,
    mErrorCategoryCheckBox,
    mCustomCategoryCheckBox,
  };
}

/**
 * Address: 0x004F5440 (FUN_004F5440)
 *
 * What it does:
 * Clears output and rebuilds committed target lines from buffered replay text
 * entries.
 */
void moho::WWinLogWindow::ResetCommittedLinesFromBuffer()
{
  if (mOutputTextControl != nullptr) {
    mOutputTextControl->Clear();
  }

  mFirstVisibleLine = 0;

  if (mOwnerTarget == nullptr) {
    return;
  }

  mOwnerTarget->ResetCommittedLinesFromReplayBuffer(mBufferedLines);
}

bool moho::WWinLogWindow::ShouldDisplayCommittedLine(const CWinLogLine& line) const
{
  if (line.categoryMask < 32) {
    const std::uint32_t categoryBit = 1u << line.categoryMask;
    if ((mEnabledCategoriesMask & categoryBit) != 0u) {
      return true;
    }
  }

  if ((mEnabledCategoriesMask & kCustomFilterCategoryBit) == 0u) {
    return false;
  }

  const msvc8::string loweredLineText = gpg::STR_ToLower(line.text.c_str());
  return std::strstr(loweredLineText.c_str(), mFilterText.c_str()) != nullptr;
}

std::wstring moho::WWinLogWindow::BuildReplayFlushText(const std::size_t startIndex) const
{
  WWinLogTextBuilder replayBuilder{};
  for (std::size_t index = startIndex; index < mBufferedLines.size(); ++index) {
    replayBuilder.WriteSpaces(index * kReplayIndentWidth);
    replayBuilder.WriteUtf8Text(mBufferedLines[index]);
    replayBuilder.WriteCodePoint(L'\n');
  }

  return replayBuilder.Finalize();
}

std::wstring moho::WWinLogWindow::BuildFormattedCommittedLineText(const CWinLogLine& line) const
{
  WWinLogTextBuilder lineBuilder{};
  const std::wstring severityPrefix(line.SeverityPrefix());
  lineBuilder.WriteWideText(severityPrefix);

  const std::size_t continuationIndent = mBufferedLines.size() * kReplayIndentWidth + severityPrefix.size();
  bool continuationLine = false;
  wchar_t decodedCodePoint = 0;
  const char* cursor = gpg::STR_DecodeUtf8Char(line.text.c_str(), decodedCodePoint);
  while (decodedCodePoint != 0) {
    if (continuationLine) {
      lineBuilder.WriteSpaces(continuationIndent);
      continuationLine = false;
    }

    lineBuilder.WriteDecodedCodePoint(decodedCodePoint);
    if (decodedCodePoint == L'\n') {
      continuationLine = true;
    }

    cursor = gpg::STR_DecodeUtf8Char(cursor, decodedCodePoint);
  }

  if (!continuationLine) {
    lineBuilder.WriteCodePoint(L'\n');
  }

  return lineBuilder.Finalize();
}

/**
 * Address: 0x004F5840 (FUN_004F5840)
 *
 * What it does:
 * Rebuilds category/filter visibility state from controls and replays matching
 * committed lines into output.
 */
void moho::WWinLogWindow::RebuildVisibleLinesFromControls()
{
  mEnabledCategoriesMask = 0;
  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    const wxCheckBoxRuntime* const checkBox = checkBoxes[index];
    if (checkBox != nullptr && checkBox->GetValue()) {
      mEnabledCategoriesMask |= (1u << index);
    }
  }

  if (mFilterTextControl != nullptr) {
    mFilterText = mFilterTextControl->GetValueUtf8Lower();
  } else {
    mFilterText.clear();
  }

  if (mOutputTextControl != nullptr) {
    mOutputTextControl->Clear();
  }

  mFirstVisibleLine = 0;
  mBufferedLines.clear();

  if (mOwnerTarget == nullptr) {
    return;
  }

  msvc8::vector<CWinLogLine> committedLinesSnapshot;
  mOwnerTarget->SnapshotCommittedLines(&committedLinesSnapshot);

  for (const CWinLogLine& line : committedLinesSnapshot) {
    AppendCommittedLine(line);
  }

  if (mOutputTextControl != nullptr) {
    mOutputTextControl->ScrollToLastPosition();
  }
}

/**
 * Address: 0x004F5AE0 (FUN_004F5AE0)
 *
 * What it does:
 * Applies one committed line against category/filter visibility and appends
 * replay/text output with preserved indentation behavior.
 */
void moho::WWinLogWindow::AppendCommittedLine(const CWinLogLine& line)
{
  while (mBufferedLines.size() > line.sequenceIndex) {
    mBufferedLines.pop_back();
  }

  if (mFirstVisibleLine > mBufferedLines.size()) {
    mFirstVisibleLine = static_cast<std::uint32_t>(mBufferedLines.size());
  }

  if (line.IsReplayEntry()) {
    if (line.isReplayEntry == 1u) {
      mBufferedLines.push_back(line.text);
    }
    return;
  }

  if (!ShouldDisplayCommittedLine(line)) {
    return;
  }

  if (mOutputTextControl == nullptr) {
    return;
  }

  if (mFirstVisibleLine < mBufferedLines.size()) {
    const wxTextAttrRuntime replayStyle = DefaultTextStyleForCategory(1u);
    (void)mOutputTextControl->SetDefaultStyle(replayStyle);
    const std::wstring replayText = BuildReplayFlushText(mFirstVisibleLine);

    mFirstVisibleLine = static_cast<std::uint32_t>(mBufferedLines.size());
    if (!replayText.empty()) {
      mOutputTextControl->AppendWide(replayText);
    }
  }

  const wxTextAttrRuntime lineStyle = DefaultTextStyleForCategory(line.categoryMask);
  (void)mOutputTextControl->SetDefaultStyle(lineStyle);
  const std::wstring formattedText = BuildFormattedCommittedLineText(line);
  mOutputTextControl->AppendWide(formattedText);

  if (line.categoryMask >= kWarningCategoryValue && moho::CFG_GetArgOption("/edit", 0, nullptr)) {
    Show(true);
  }
}

/**
 * Address: 0x004F6470 (FUN_004F6470)
 *
 * What it does:
 * Merges pending lines into committed history and refreshes output when the
 * committed count changed.
 */
void moho::WWinLogWindow::OnTargetPendingLinesChanged(const CLogAdditionEvent& event)
{
  (void)event;
  if (mOwnerTarget == nullptr) {
    return;
  }

  const std::size_t previousCommittedLineCount = mOwnerTarget->CommittedLineCount();
  mOwnerTarget->MergePendingLines();
  if (previousCommittedLineCount != mOwnerTarget->CommittedLineCount()) {
    RebuildVisibleLinesFromControls();
  }
}

void moho::WWinLogWindow::OnTargetPendingLinesChanged()
{
  const CLogAdditionEvent event{};
  OnTargetPendingLinesChanged(event);
}

/**
 * Address: 0x008CD8C0 (FUN_008CD8C0)
 * Mangled: ??0WSupComFrame@@QAE@PBDABVwxPoint@@ABVwxSize@@J@Z
 *
 * What it does:
 * Creates one SupCom frame runtime object with constructor-equivalent startup
 * semantics: UTF-8 title lane, position/style lanes, sync-flag zeroing,
 * min-drag size hints, and startup icon-resource assignment.
 */
WSupComFrame* WX_CreateSupComFrame(
  const char* const title, const wxPoint& position, const wxSize& size, const std::int32_t style
)
{
  auto* const frame = new WSupComFrameRuntime(title, position, size, style);
  frame->SetSizeHints(moho::wnd_MinDragWidth, moho::wnd_MinDragHeight, -1, -1, -1, -1);
  return frame;
}

namespace
{
  constexpr unsigned int kSupComFrameMessageSize = WM_SIZE;
  constexpr unsigned int kSupComFrameMessageActivateApp = WM_ACTIVATEAPP;
  constexpr unsigned int kSupComFrameMessageSysCommand = WM_SYSCOMMAND;
  constexpr unsigned int kSupComFrameMessageExitSizeMove = WM_EXITSIZEMOVE;
  constexpr unsigned int kSupComFrameSysCommandToggleLogDialog = 0x1u;
  constexpr unsigned int kSupComFrameSysCommandLuaDebugger = 0x2u;
  constexpr unsigned int kSupComFrameSysCommandKeyMenu = SC_KEYMENU;

  constexpr const char* kSupComFrameWidthPreferenceKey = "Windows.Main.width";
  constexpr const char* kSupComFrameHeightPreferenceKey = "Windows.Main.height";
  constexpr const char* kSupComFrameMaximizedPreferenceKey = "Windows.Main.maximized";
  constexpr const char* kSupComFrameToggleLogDialogCommand = "WIN_ToggleLogDialog";
  constexpr const char* kSupComFrameLuaDebuggerCommand = "SC_LuaDebugger";
  constexpr const char* kSupComFrameCursorLockPreferenceKey = "lock_fullscreen_cursor_to_window";

  /**
   * Address: 0x008CDBE0 (FUN_008CDBE0)
   *
   * What it does:
   * Clamps SupCom frame client dimensions to drag minima, propagates size to
   * the active viewport, then rebuilds one GAL context head and reinitializes
   * D3D device state.
   */
  void SyncSupComFrameClientSizeAndViewport(WSupComFrame& frame)
  {
    std::int32_t width = 0;
    std::int32_t height = 0;
    frame.DoGetClientSize(&width, &height);

    if (width < moho::wnd_MinDragWidth) {
      width = moho::wnd_MinDragWidth;
    }
    if (height < moho::wnd_MinDragHeight) {
      height = moho::wnd_MinDragHeight;
    }

    frame.DoSetClientSize(width, height);
    if (moho::ren_Viewport != nullptr) {
      moho::ren_Viewport->DoSetSize(-1, -1, width, height, 0);
    }

    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() > 0) {
      gpg::gal::Head& head = context.GetHead(0);
      head.mWidth = width;
      head.mHeight = height;
    }

    moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice();
    if (d3dDevice == nullptr) {
      return;
    }

    d3dDevice->Clear();
    d3dDevice->InitContext(&context);
  }

  /**
   * Address: 0x008D1D70 (FUN_008D1D70)
   *
   * What it does:
   * Applies cursor clipping for active SupCom frame focus: locks to main
   * window rectangle when one windowed head is active and the cursor-lock
   * option is enabled, otherwise clears clip bounds.
   */
  void UpdateSupComCursorClipForActivation()
  {
    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() <= 0) {
      return;
    }

    const gpg::gal::Head& head = context.GetHead(0);
    RECT clipRect{};
    RECT* clipRectPtr = nullptr;
    if (
      context.GetHeadCount() == 1 && head.mWindowed
      && moho::OPTIONS_GetInt(kSupComFrameCursorLockPreferenceKey) == 1 && moho::sMainWindow != nullptr
    ) {
      const HWND mainWindowHandle =
        reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
      if (mainWindowHandle != nullptr) {
        ::GetWindowRect(mainWindowHandle, &clipRect);
        clipRectPtr = &clipRect;
      }
    }

    ::ClipCursor(clipRectPtr);
  }
} // namespace

/**
 * Address: 0x008CDD40 (FUN_008CDD40, WSupComFrame::MSWWindowProc)
 * Mangled: ?MSWWindowProc@WSupComFrame@@UAEJIIJ@Z
 *
 * What it does:
 * Handles SupCom frame resize/maximize/app-activation/system-command routing,
 * persists window preference keys, and forwards unhandled messages to base
 * frame dispatch.
 */
long WSupComFrame::MSWWindowProc(const unsigned int message, const unsigned int wParam, const long lParam)
{
  auto dispatchBase = [this, message, wParam, lParam]() -> long {
    return wxTopLevelWindowRuntime::MSWWindowProc(message, wParam, lParam);
  };

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (!moho::sDeviceLock && moho::ren_Viewport != nullptr && gpg::gal::Device::IsReady()) {
    if (gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance(); galDevice != nullptr) {
      if (gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
          activeContext != nullptr && activeContext->GetHeadCount() > 0) {
        (void)activeContext->GetHead(0);
      }
    }

    if (mPendingMaximizeSync != 0 && message == kSupComFrameMessageExitSizeMove) {
      SyncSupComFrameClientSizeAndViewport(*this);

      if (preferences != nullptr) {
        const wxSize clientSize = GetClientSize();
        preferences->SetInteger(msvc8::string(kSupComFrameWidthPreferenceKey), clientSize.x);
        preferences->SetInteger(msvc8::string(kSupComFrameHeightPreferenceKey), clientSize.y);
      }

      if (moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice(); d3dDevice != nullptr) {
        (void)d3dDevice->Clear2(false);
      }

      mPendingMaximizeSync = 0;
    } else if (message == kSupComFrameMessageSize && wParam == SIZE_MAXIMIZED) {
      SyncSupComFrameClientSizeAndViewport(*this);
      if (preferences != nullptr) {
        preferences->SetBoolean(msvc8::string(kSupComFrameMaximizedPreferenceKey), true);
      }
      mPersistedMaximizeSync = 1;
    }

    if (mPendingMaximizeSync == 0 && message == kSupComFrameMessageSize) {
      if (wParam == SIZE_RESTORED && mPersistedMaximizeSync != 0) {
        SyncSupComFrameClientSizeAndViewport(*this);
        if (preferences != nullptr) {
          const wxSize clientSize = GetClientSize();
          preferences->SetInteger(msvc8::string(kSupComFrameWidthPreferenceKey), clientSize.x);
          preferences->SetInteger(msvc8::string(kSupComFrameHeightPreferenceKey), clientSize.y);
          preferences->SetBoolean(msvc8::string(kSupComFrameMaximizedPreferenceKey), false);
        }
        mPersistedMaximizeSync = 0;
      }

      return dispatchBase();
    }
  }

  if (message == kSupComFrameMessageActivateApp) {
    const bool isActive = wParam != 0;
    mIsApplicationActive = isActive ? 1 : 0;
    if (isActive) {
      UpdateSupComCursorClipForActivation();
    } else {
      ::ClipCursor(nullptr);
    }
    return dispatchBase();
  }

  if (message != kSupComFrameMessageSysCommand) {
    return dispatchBase();
  }

  if (wParam == kSupComFrameSysCommandToggleLogDialog) {
    moho::CON_Execute(kSupComFrameToggleLogDialogCommand);
    return dispatchBase();
  }

  if (wParam == kSupComFrameSysCommandLuaDebugger) {
    moho::CON_Execute(kSupComFrameLuaDebuggerCommand);
    return dispatchBase();
  }

  if (wParam != kSupComFrameSysCommandKeyMenu) {
    return dispatchBase();
  }

  gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
  if (galDevice == nullptr) {
    return dispatchBase();
  }

  gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
  if (activeContext == nullptr || activeContext->GetHeadCount() <= 0 || !activeContext->GetHead(0).mWindowed) {
    return dispatchBase();
  }

  return 0;
}

/**
 * Address family:
 * - 0x004F7210 (FUN_004F7210)
 * - 0x004F72D0 (FUN_004F72D0)
 *
 * What it does:
 * Unlinks one managed slot from its owner slot chain.
 */
void moho::ManagedWindowSlot::UnlinkFromOwner() noexcept
{
  if (ownerHeadLink == nullptr || IsInlineHeadLinkSentinel(ownerHeadLink)) {
    ownerHeadLink = nullptr;
    nextInOwnerChain = nullptr;
    return;
  }

  ManagedWindowSlot** link = ownerHeadLink;
  while (*link != this) {
    if (*link == nullptr) {
      ownerHeadLink = nullptr;
      nextInOwnerChain = nullptr;
      return;
    }
    link = &(*link)->nextInOwnerChain;
  }

  *link = nextInOwnerChain;
  ownerHeadLink = nullptr;
  nextInOwnerChain = nullptr;
}

/**
 * Address context:
 * - destructor slot-clear writes in 0x004F40A0 / 0x004F4230
 *
 * What it does:
 * Clears both link lanes to the inert slot state.
 */
void moho::ManagedWindowSlot::Clear() noexcept
{
  ownerHeadLink = nullptr;
  nextInOwnerChain = nullptr;
}

moho::WWinManagedDialog* moho::WWinManagedDialog::FromManagedSlotHeadLink(ManagedWindowSlot** const ownerHeadLink) noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == NullManagedSlotHeadLinkSentinel()) {
    return nullptr;
  }

  const std::uintptr_t linkAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  return reinterpret_cast<WWinManagedDialog*>(linkAddress - offsetof(WWinManagedDialog, mManagedSlotsHead));
}

moho::ManagedWindowSlot** moho::WWinManagedDialog::NullManagedSlotHeadLinkSentinel() noexcept
{
  return reinterpret_cast<ManagedWindowSlot**>(offsetof(WWinManagedDialog, mManagedSlotsHead));
}

/**
 * Address: 0x004F7070 (FUN_004F7070)
 *
 * What it does:
 * Returns the current number of dialog-managed registry slots.
 */
std::size_t moho::WWinManagedDialog::ManagedSlotCount()
{
  return managedWindows.size();
}

/**
 * Address: 0x004F70A0 (FUN_004F70A0)
 *
 * What it does:
 * Appends one dialog-managed registry slot and links it to `ownerHeadLink`.
 */
void moho::WWinManagedDialog::AppendManagedSlotForOwner(ManagedWindowSlot** const ownerHeadLink)
{
  AppendManagedSlot<WWinManagedDialog>(managedWindows, ownerHeadLink);
}

/**
 * Address: 0x004F3F50 (FUN_004F3F50, WWinManagedDialog ctor tail)
 *
 * What it does:
 * Registers this dialog owner head in the global managed-dialog slot registry.
 */
void moho::WWinManagedDialog::RegisterManagedOwnerSlot()
{
  RegisterManagedOwnerSlotImpl<WWinManagedDialog>(managedWindows, &mManagedSlotsHead);
}

/**
 * Address: 0x004F40A0 (FUN_004F40A0, WWinManagedDialog dtor core)
 *
 * What it does:
 * Unlinks and clears every managed slot currently chained to this dialog.
 */
void moho::WWinManagedDialog::ReleaseManagedOwnerSlots()
{
  ReleaseManagedOwnerSlotChain(mManagedSlotsHead);
}

void moho::WWinManagedDialog::DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots)
{
  DestroyManagedRuntimeCollection<WWinManagedDialog>(slots);
}

moho::WWinManagedFrame* moho::WWinManagedFrame::FromManagedSlotHeadLink(ManagedWindowSlot** const ownerHeadLink) noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == NullManagedSlotHeadLinkSentinel()) {
    return nullptr;
  }

  const std::uintptr_t linkAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  return reinterpret_cast<WWinManagedFrame*>(linkAddress - offsetof(WWinManagedFrame, mManagedSlotsHead));
}

moho::ManagedWindowSlot** moho::WWinManagedFrame::NullManagedSlotHeadLinkSentinel() noexcept
{
  return reinterpret_cast<ManagedWindowSlot**>(offsetof(WWinManagedFrame, mManagedSlotsHead));
}

/**
 * Address: 0x004F7140 (FUN_004F7140)
 *
 * What it does:
 * Returns the current number of frame-managed registry slots.
 */
std::size_t moho::WWinManagedFrame::ManagedSlotCount()
{
  return managedFrames.size();
}

/**
 * Address: 0x004F7170 (FUN_004F7170)
 *
 * What it does:
 * Appends one frame-managed registry slot and links it to `ownerHeadLink`.
 */
void moho::WWinManagedFrame::AppendManagedSlotForOwner(ManagedWindowSlot** const ownerHeadLink)
{
  AppendManagedSlot<WWinManagedFrame>(managedFrames, ownerHeadLink);
}

/**
 * Address: 0x004F40E0 (FUN_004F40E0, WWinManagedFrame ctor tail)
 *
 * What it does:
 * Registers this frame owner head in the global managed-frame slot registry.
 */
void moho::WWinManagedFrame::RegisterManagedOwnerSlot()
{
  RegisterManagedOwnerSlotImpl<WWinManagedFrame>(managedFrames, &mManagedSlotsHead);
}

/**
 * Address: 0x004F4230 (FUN_004F4230, WWinManagedFrame dtor core)
 *
 * What it does:
 * Unlinks and clears every managed slot currently chained to this frame.
 */
void moho::WWinManagedFrame::ReleaseManagedOwnerSlots()
{
  ReleaseManagedOwnerSlotChain(mManagedSlotsHead);
}

void moho::WWinManagedFrame::DestroyManagedOwners(msvc8::vector<ManagedWindowSlot>& slots)
{
  DestroyManagedRuntimeCollection<WWinManagedFrame>(slots);
}
