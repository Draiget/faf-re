#include "moho/ui/UiRuntimeTypes.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace
{
  gpg::RType* gCMauiGroupTypeCache = nullptr;
  gpg::RType* gCMauiHistogramTypeCache = nullptr;
  gpg::RType* gCMauiItemListTypeCache = nullptr;

  template <typename T>
  [[nodiscard]] gpg::RType* CachedUpcastTypeFromTypeInfo()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCMauiControlUpcastType()
  {
    if (moho::CMauiControl::sType == nullptr) {
      moho::CMauiControl::sType = gpg::LookupRType(typeid(moho::CMauiControl));
    }
    return moho::CMauiControl::sType;
  }

  /**
   * Address: 0x00786160 (FUN_00786160)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiBorder`.
   */
  [[nodiscard]] gpg::RType* CachedCMauiBorderUpcastType()
  {
    if (moho::CMauiBorder::sType == nullptr) {
      moho::CMauiBorder::sType = gpg::LookupRType(typeid(moho::CMauiBorder));
    }
    return moho::CMauiBorder::sType;
  }

  /**
   * Address: 0x0086A380 (FUN_0086A380)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for
   * `CLuaWldUIProvider`.
   */
  [[nodiscard]] gpg::RType* CachedCLuaWldUIProviderUpcastType()
  {
    if (moho::CLuaWldUIProvider::sType == nullptr) {
      moho::CLuaWldUIProvider::sType = gpg::LookupRType(typeid(moho::CLuaWldUIProvider));
    }
    return moho::CLuaWldUIProvider::sType;
  }

  /**
   * Address: 0x0086ABA0 (FUN_0086ABA0)
   *
   * What it does:
   * Secondary cache accessor returning the reflection descriptor for
   * `CLuaWldUIProvider`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCLuaWldUIProviderUpcastTypeSecondary()
  {
    if (moho::CLuaWldUIProvider::sType == nullptr) {
      moho::CLuaWldUIProvider::sType = gpg::LookupRType(typeid(moho::CLuaWldUIProvider));
    }
    return moho::CLuaWldUIProvider::sType;
  }

  /**
   * Address: 0x0078B440 (FUN_0078B440)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `EMauiScrollAxis`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedEMauiScrollAxisType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::EMauiScrollAxis));
    }
    return cached;
  }

  /**
   * Address: 0x0078D920 (FUN_0078D920)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiCursor`.
   */
  [[nodiscard]] gpg::RType* CachedCMauiCursorUpcastType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CMauiCursor));
    }
    return cached;
  }

  /**
   * Address: 0x0078E620 (FUN_0078E620)
   *
   * What it does:
   * Returns the cached reflection descriptor for `CMauiLuaDragger` by
   * resolved type-name lookup.
   */
  [[nodiscard]] gpg::RType* CachedCMauiLuaDraggerUpcastType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::REF_FindTypeNamed("CMauiLuaDragger");
      if (cached == nullptr) {
        cached = gpg::REF_FindTypeNamed("Moho::CMauiLuaDragger");
      }
    }
    return cached;
  }

  /**
   * Address: 0x0078EB20 (FUN_0078EB20)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `EMauiKeyCode`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedEMauiKeyCodeType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::EMauiKeyCode));
    }
    return cached;
  }

  /**
   * Address: 0x00794E40 (FUN_00794E40)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiEdit`.
   */
  [[nodiscard]] gpg::RType* CachedCMauiEditType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CMauiEdit));
    }
    return cached;
  }

  /**
   * Address: 0x00795FA0 (FUN_00795FA0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `EMauiEventType`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedEMauiEventType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::EMauiEventType));
    }
    return cached;
  }

  /**
   * Address: 0x007970D0 (FUN_007970D0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiGroup`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCMauiGroupTypePrimary()
  {
    if (gCMauiGroupTypeCache == nullptr) {
      gCMauiGroupTypeCache = gpg::LookupRType(typeid(moho::CMauiGroup));
    }
    return gCMauiGroupTypeCache;
  }

  /**
   * Address: 0x007974F0 (FUN_007974F0)
   *
   * What it does:
   * Secondary cache accessor returning the reflection descriptor for
   * `CMauiGroup`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCMauiGroupTypeSecondary()
  {
    if (gCMauiGroupTypeCache == nullptr) {
      gCMauiGroupTypeCache = gpg::LookupRType(typeid(moho::CMauiGroup));
    }
    return gCMauiGroupTypeCache;
  }

  /**
   * Address: 0x007975D0 (FUN_007975D0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiHistogram`.
   */
  [[nodiscard]] gpg::RType* CachedCMauiHistogramTypePrimary()
  {
    if (gCMauiHistogramTypeCache == nullptr) {
      gCMauiHistogramTypeCache = gpg::LookupRType(typeid(moho::CMauiHistogram));
    }
    return gCMauiHistogramTypeCache;
  }

  /**
   * Address: 0x00798240 (FUN_00798240)
   *
   * What it does:
   * Secondary cache accessor returning the reflection descriptor for
   * `CMauiHistogram`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCMauiHistogramTypeSecondary()
  {
    if (gCMauiHistogramTypeCache == nullptr) {
      gCMauiHistogramTypeCache = gpg::LookupRType(typeid(moho::CMauiHistogram));
    }
    return gCMauiHistogramTypeCache;
  }

  /**
   * Address: 0x00799030 (FUN_00799030)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiItemList`.
   */
  [[nodiscard]] gpg::RType* CachedCMauiItemListTypePrimary()
  {
    if (gCMauiItemListTypeCache == nullptr) {
      gCMauiItemListTypeCache = gpg::LookupRType(typeid(moho::CMauiItemList));
    }
    return gCMauiItemListTypeCache;
  }

  /**
   * Address: 0x0079C8F0 (FUN_0079C8F0)
   *
   * What it does:
   * Secondary cache accessor returning the reflection descriptor for
   * `CMauiItemList`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCMauiItemListTypeSecondary()
  {
    if (gCMauiItemListTypeCache == nullptr) {
      gCMauiItemListTypeCache = gpg::LookupRType(typeid(moho::CMauiItemList));
    }
    return gCMauiItemListTypeCache;
  }

  /**
   * Address: 0x007A23C0 (FUN_007A23C0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiScrollbar`.
   */
  [[nodiscard]] gpg::RType* CachedCMauiScrollbarType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CMauiScrollbar));
    }
    return cached;
  }

  /**
   * Address: 0x007A29B0 (FUN_007A29B0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CMauiText`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCMauiTextType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CMauiText));
    }
    return cached;
  }

  /**
   * Address: 0x008512F0 (FUN_008512F0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CUIMapPreview`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCUIMapPreviewType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CUIMapPreview));
    }
    return cached;
  }

  [[nodiscard]] void* UpcastObjectRef(const gpg::RRef* const sourceRef, gpg::RType* const targetType)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, targetType);
    return upcast.mObj;
  }

  /**
   * Address: 0x00783F20 (FUN_00783F20)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiControl*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiControlObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiControlUpcastType());
  }

  /**
   * Address: 0x00783F60 (FUN_00783F60)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiBitmap*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiBitmapObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedUpcastTypeFromTypeInfo<moho::CMauiBitmap>());
  }

  /**
   * Address: 0x00786310 (FUN_00786310)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiBorder*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiBorderObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiBorderUpcastType());
  }

  /**
   * Address: 0x0078DAD0 (FUN_0078DAD0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiCursor*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiCursorObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiCursorUpcastType());
  }

  /**
   * Address: 0x0078EB40 (FUN_0078EB40)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiLuaDragger*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiLuaDraggerObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiLuaDraggerUpcastType());
  }

  /**
   * Address: 0x0078EB80 (FUN_0078EB80)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiFrame*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiFrameObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedUpcastTypeFromTypeInfo<moho::CMauiFrame>());
  }

  /**
   * Address: 0x007959B0 (FUN_007959B0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiEdit*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiEditObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiEditType());
  }

  /**
   * Address: 0x00798BE0 (FUN_00798BE0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiHistogram*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiHistogramObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiHistogramTypePrimary());
  }

  /**
   * Address: 0x0079CAC0 (FUN_0079CAC0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiItemList*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiItemListObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiItemListTypePrimary());
  }

  /**
   * Address: 0x0079EC20 (FUN_0079EC20)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiMesh*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiMeshObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedUpcastTypeFromTypeInfo<moho::CMauiMesh>());
  }

  /**
   * Address: 0x007A02A0 (FUN_007A02A0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiMovie*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiMovieObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedUpcastTypeFromTypeInfo<moho::CMauiMovie>());
  }

  /**
   * Address: 0x007A28C0 (FUN_007A28C0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CMauiScrollbar*`.
   */
  [[maybe_unused]] void* UpcastRefToCMauiScrollbarObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCMauiScrollbarType());
  }

  /**
   * Address: 0x0086AD40 (FUN_0086AD40)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CLuaWldUIProvider*`.
   */
  [[maybe_unused]] void* UpcastRefToCLuaWldUIProviderObject(const gpg::RRef* const sourceRef)
  {
    return UpcastObjectRef(sourceRef, CachedCLuaWldUIProviderUpcastType());
  }
} // namespace
