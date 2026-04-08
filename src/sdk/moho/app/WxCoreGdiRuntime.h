#pragma once

#include <cstddef>
#include <cstdint>

/**
 * Runtime class-info placeholder used by recovered wx core/GDI lanes.
 */
struct wxClassInfoRuntime
{
  void* lane = nullptr;
};

static_assert(sizeof(wxClassInfoRuntime) == 0x4, "wxClassInfoRuntime size must be 0x4");

/**
 * Minimal recovered wxObject runtime base.
 */
class wxObjectRuntime
{
public:
  /**
   * Address: 0x0042AD90 (FUN_0042AD90)
   * Mangled: ??0wxObject@@QAE@@Z
   *
   * What it does:
   * Initializes base wx object lanes and clears ref-data ownership.
   */
  wxObjectRuntime();

  /**
   * Address: 0x0042ADA0 (FUN_0042ADA0)
   * Mangled: ??1wxObject@@QAE@XZ
   *
   * What it does:
   * Releases ref-data ownership through the shared unref lane.
   */
  virtual ~wxObjectRuntime();

protected:
  void ReleaseRefData() noexcept;

  void* mRefData = nullptr;
};

static_assert(offsetof(wxObjectRuntime, mRefData) == 0x4, "wxObjectRuntime::mRefData offset must be 0x4");
static_assert(sizeof(wxObjectRuntime) == 0x8, "wxObjectRuntime size must be 0x8");

/**
 * Minimal recovered wx GDI object runtime base.
 */
class wxGDIObjectRuntime : public wxObjectRuntime
{
public:
  /**
   * Address: 0x0042AE50 (FUN_0042AE50)
   * Mangled: ??0wxGDIObject@@QAE@@Z
   *
   * What it does:
   * Seeds the runtime-visible lane to false with empty ref-data ownership.
   */
  wxGDIObjectRuntime();

  /**
   * Address: 0x0042AE70 (FUN_0042AE70)
   * Mangled: ?RealizeResource@wxGDIObject@@UAE_NXZ
   *
   * What it does:
   * Default base implementation reports no realizable native resource.
   */
  [[nodiscard]] virtual bool RealizeResource();

  /**
   * Address: 0x0042AE80 (FUN_0042AE80)
   * Mangled: ?FreeResource@wxGDIObject@@UAE_NK@Z
   *
   * What it does:
   * Default base implementation reports no resource to free.
   */
  [[nodiscard]] virtual bool FreeResource(std::uintptr_t resourceHandle);

  /**
   * Address: 0x0042AE90 (FUN_0042AE90)
   * Mangled: ?IsFree@wxGDIObject@@UBE_NXZ
   *
   * What it does:
   * Base implementation reports this object as not free.
   */
  [[nodiscard]] virtual bool IsFree() const;

  /**
   * Address: 0x0042AEA0 (FUN_0042AEA0)
   * Mangled: ?GetResourceHandle@wxGDIObject@@UBEKXZ
   *
   * What it does:
   * Base implementation exposes no native resource handle.
   */
  [[nodiscard]] virtual std::uintptr_t GetResourceHandle() const;

  /**
   * Address: 0x0042AEB0 (FUN_0042AEB0)
   * Mangled: ?GetVisible@wxGDIObject@@QBE_NXZ
   *
   * What it does:
   * Returns the runtime visibility lane.
   */
  [[nodiscard]] virtual bool GetVisible() const;

  /**
   * Address: 0x0042AEC0 (FUN_0042AEC0)
   * Mangled: ?SetVisible@wxGDIObject@@QAEE_N@Z
   *
   * What it does:
   * Stores one runtime visibility value and returns it.
   */
  virtual bool SetVisible(bool visible);

  /**
   * Address: 0x0042AED0 (FUN_0042AED0)
   * Mangled: ?GetClassInfo@wxGDIObject@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns static class-info storage for wxGDIObject runtime checks.
   */
  [[nodiscard]] virtual const wxClassInfoRuntime* GetClassInfo() const;

protected:
  std::uint8_t mVisible = 0;
  std::uint8_t mPadding09[3]{};
};

static_assert(offsetof(wxGDIObjectRuntime, mVisible) == 0x8, "wxGDIObjectRuntime::mVisible offset must be 0x8");
static_assert(sizeof(wxGDIObjectRuntime) == 0xC, "wxGDIObjectRuntime size must be 0xC");

/**
 * Minimal recovered wxFontBase runtime lane.
 */
class wxFontBaseRuntime : public wxGDIObjectRuntime
{
public:
  /**
   * Address: 0x0042AF20 (FUN_0042AF20)
   * Mangled: ?SetNoAntiAliasing@wxFontBase@@UAEX_N@Z
   *
   * What it does:
   * Base implementation accepts but ignores anti-aliasing policy.
   */
  virtual void SetNoAntiAliasing(bool disabled);

  /**
   * Address: 0x0042AF30 (FUN_0042AF30)
   * Mangled: ?GetNoAntiAliasing@wxFontBase@@UBE_NXZ
   *
   * What it does:
   * Base implementation reports anti-aliasing enabled.
   */
  [[nodiscard]] virtual bool GetNoAntiAliasing() const;

  /**
   * Address: 0x0042AFE0 (FUN_0042AFE0)
   * Mangled: ??1wxFontBase@@UAE@XZ
   *
   * What it does:
   * Destroys wxFontBase through wxObject ref-data release semantics.
   */
  ~wxFontBaseRuntime() override;
};

/**
 * Minimal recovered wxFont runtime lane.
 */
class wxFontRuntimeObject : public wxFontBaseRuntime
{
public:
  /**
   * Address: 0x0042AF40 (FUN_0042AF40)
   * Mangled: ??0wxFont@@QAE@@Z
   *
   * What it does:
   * Initializes base lanes and performs font runtime init hook.
   */
  wxFontRuntimeObject();

  /**
   * Address: 0x0096E9F0 (FUN_0096E9F0)
   * Mangled: ??1wxFont@@QAE@@Z
   *
   * What it does:
   * Tears down wxFont runtime lanes and releases base wxObject ref-data state.
   */
  ~wxFontRuntimeObject() override;

  /**
   * Address: 0x0042AF90 (FUN_0042AF90)
   * Mangled: ?GetClassInfo@wxFont@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns static class-info storage for wxFont runtime checks.
   */
  [[nodiscard]] const wxClassInfoRuntime* GetClassInfo() const override;

private:
  void Init() noexcept;
};

static_assert(sizeof(wxFontRuntimeObject) == 0xC, "wxFontRuntimeObject size must be 0xC");
