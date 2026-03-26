#include "WxRuntimeTypes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <new>
#include <system_error>
#include <unordered_map>

#include "gpg/core/containers/String.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  constexpr std::uintptr_t kInlineHeadLinkSentinelMax = 0x10000u;
  void* gCLogAdditionEventClassInfoTable[1] = {nullptr};

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
      gSupComFrameStateByFrame.erase(this);
      delete this;
      return true;
    }

    bool Show(const bool show) override
    {
      EnsureSupComFrameState(this).visible = show;
      return true;
    }

    void SetTitle(const void* const title) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      const auto* const titleRuntime = static_cast<const wxStringRuntime*>(title);
      state.title.assign(titleRuntime != nullptr ? titleRuntime->c_str() : L"");
    }

    void SetName(const void* const name) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      const auto* const nameRuntime = static_cast<const wxStringRuntime*>(name);
      state.name.assign(nameRuntime != nullptr ? nameRuntime->c_str() : L"");
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

    void DoGetClientSize(std::int32_t* const outWidth, std::int32_t* const outHeight) override
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

msvc8::vector<moho::ManagedWindowSlot> moho::managedWindows{};
msvc8::vector<moho::ManagedWindowSlot> moho::managedFrames{};
wxWindowBase* moho::sMainWindow = nullptr;
moho::WRenViewport* moho::ren_Viewport = nullptr;

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
