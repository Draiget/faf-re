#include "WxCoreGdiRuntime.h"

namespace
{
  wxClassInfoRuntime gWxGdiObjectClassInfo{};
  wxClassInfoRuntime gWxFontClassInfo{};

  struct WxFontRefDataRuntimeView
  {
    std::uint8_t reserved00To23[0x24];
    std::uintptr_t nativeHandle = 0;
  };
  static_assert(
    offsetof(WxFontRefDataRuntimeView, nativeHandle) == 0x24,
    "WxFontRefDataRuntimeView::nativeHandle offset must be 0x24"
  );

  /**
   * Address: 0x0096EA50 (FUN_0096EA50, GetHfontOf)
   *
   * What it does:
   * Returns the native HFONT handle lane from wxFont ref-data storage, or zero
   * when the font object has no shared ref-data.
   */
  [[maybe_unused]] std::uintptr_t GetHfontOf(
    const void* const refData
  )
  {
    const auto* const fontRefData = reinterpret_cast<const WxFontRefDataRuntimeView*>(refData);
    return (fontRefData != nullptr) ? fontRefData->nativeHandle : 0u;
  }
} // namespace

/**
 * Address: 0x0042AD90 (FUN_0042AD90)
 * Mangled: ??0wxObject@@QAE@@Z
 *
 * What it does:
 * Initializes base wx object lanes and clears ref-data ownership.
 */
wxObjectRuntime::wxObjectRuntime()
  : mRefData(nullptr)
{}

/**
 * Address: 0x0042ADA0 (FUN_0042ADA0)
 * Mangled: ??1wxObject@@QAE@XZ
 *
 * What it does:
 * Releases ref-data ownership through the shared unref lane.
 */
wxObjectRuntime::~wxObjectRuntime()
{
  ReleaseRefData();
}

void wxObjectRuntime::ReleaseRefData() noexcept
{
  mRefData = nullptr;
}

/**
 * Address: 0x0042AE50 (FUN_0042AE50)
 * Mangled: ??0wxGDIObject@@QAE@@Z
 *
 * What it does:
 * Seeds the runtime-visible lane to false with empty ref-data ownership.
 */
wxGDIObjectRuntime::wxGDIObjectRuntime()
{
  mRefData = nullptr;
  mVisible = 0;
}

/**
 * Address: 0x0042AE70 (FUN_0042AE70)
 * Mangled: ?RealizeResource@wxGDIObject@@UAE_NXZ
 *
 * What it does:
 * Default base implementation reports no realizable native resource.
 */
bool wxGDIObjectRuntime::RealizeResource()
{
  return false;
}

/**
 * Address: 0x0042AE80 (FUN_0042AE80)
 * Mangled: ?FreeResource@wxGDIObject@@UAE_NK@Z
 *
 * What it does:
 * Default base implementation reports no resource to free.
 */
bool wxGDIObjectRuntime::FreeResource(
  const std::uintptr_t resourceHandle
)
{
  (void)resourceHandle;
  return false;
}

/**
 * Address: 0x0042AE90 (FUN_0042AE90)
 * Mangled: ?IsFree@wxGDIObject@@UBE_NXZ
 *
 * What it does:
 * Base implementation reports this object as not free.
 */
bool wxGDIObjectRuntime::IsFree() const
{
  return false;
}

/**
 * Address: 0x0042AEA0 (FUN_0042AEA0)
 * Mangled: ?GetResourceHandle@wxGDIObject@@UBEKXZ
 *
 * What it does:
 * Base implementation exposes no native resource handle.
 */
std::uintptr_t wxGDIObjectRuntime::GetResourceHandle() const
{
  return 0;
}

/**
 * Address: 0x0042AEB0 (FUN_0042AEB0)
 * Mangled: ?GetVisible@wxGDIObject@@QBE_NXZ
 *
 * What it does:
 * Returns the runtime visibility lane.
 */
bool wxGDIObjectRuntime::GetVisible() const
{
  return mVisible != 0;
}

/**
 * Address: 0x0042AEC0 (FUN_0042AEC0)
 * Mangled: ?SetVisible@wxGDIObject@@QAEE_N@Z
 *
 * What it does:
 * Stores one runtime visibility value and returns it.
 */
bool wxGDIObjectRuntime::SetVisible(
  const bool visible
)
{
  mVisible = visible ? 1 : 0;
  return visible;
}

/**
 * Address: 0x0042AED0 (FUN_0042AED0)
 * Mangled: ?GetClassInfo@wxGDIObject@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns static class-info storage for wxGDIObject runtime checks.
 */
const wxClassInfoRuntime* wxGDIObjectRuntime::GetClassInfo() const
{
  return &gWxGdiObjectClassInfo;
}

/**
 * Address: 0x0042AF20 (FUN_0042AF20)
 * Mangled: ?SetNoAntiAliasing@wxFontBase@@UAEX_N@Z
 *
 * What it does:
 * Base implementation accepts but ignores anti-aliasing policy.
 */
void wxFontBaseRuntime::SetNoAntiAliasing(
  const bool disabled
)
{
  (void)disabled;
}

/**
 * Address: 0x0042AF30 (FUN_0042AF30)
 * Mangled: ?GetNoAntiAliasing@wxFontBase@@UBE_NXZ
 *
 * What it does:
 * Base implementation reports anti-aliasing enabled.
 */
bool wxFontBaseRuntime::GetNoAntiAliasing() const
{
  return false;
}

/**
 * Address: 0x0042AFE0 (FUN_0042AFE0)
 * Mangled: ??1wxFontBase@@UAE@XZ
 *
 * What it does:
 * Destroys wxFontBase through wxObject ref-data release semantics.
 */
wxFontBaseRuntime::~wxFontBaseRuntime() = default;

/**
 * Address: 0x0042AF40 (FUN_0042AF40)
 * Mangled: ??0wxFont@@QAE@@Z
 *
 * What it does:
 * Initializes base lanes and performs font runtime init hook.
 */
wxFontRuntimeObject::wxFontRuntimeObject()
{
  mRefData = nullptr;
  mVisible = 0;
  Init();
}

/**
 * Address: 0x0096E9F0 (FUN_0096E9F0)
 * Mangled: ??1wxFont@@QAE@@Z
 *
 * What it does:
 * Tears down wxFont runtime lanes and releases base wxObject ref-data state.
 */
wxFontRuntimeObject::~wxFontRuntimeObject() = default;

/**
 * Address: 0x0042AF90 (FUN_0042AF90)
 * Mangled: ?GetClassInfo@wxFont@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns static class-info storage for wxFont runtime checks.
 */
const wxClassInfoRuntime* wxFontRuntimeObject::GetClassInfo() const
{
  return &gWxFontClassInfo;
}

void wxFontRuntimeObject::Init() noexcept {}
