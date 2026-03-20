#include "RDebugOverlayClass.h"

#include <typeinfo>

namespace
{
  [[nodiscard]] gpg::RType* CachedRDebugOverlayClassType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::RDebugOverlayClass));
    }
    return sType;
  }

  [[nodiscard]] moho::TDatList<moho::RDebugOverlayClass, void>& GlobalDebugOverlayClassList()
  {
    static moho::TDatList<moho::RDebugOverlayClass, void> sOverlayClassList;
    return sOverlayClassList;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0064C170 (FUN_0064C170, ?GetClass@RDebugOverlayClass@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* RDebugOverlayClass::GetClass() const
  {
    return CachedRDebugOverlayClassType();
  }

  /**
   * Address: 0x0064C190 (FUN_0064C190, ?GetDerivedObjectRef@RDebugOverlayClass@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef RDebugOverlayClass::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0064C4D0 (FUN_0064C4D0, scalar deleting body)
   */
  RDebugOverlayClass::~RDebugOverlayClass() = default;

  /**
   * Address: 0x00651920 (FUN_00651920)
   */
  void RDebugOverlayClass::RegisterOverlayClassToken(const char* const overlayToken)
  {
    mOverlayToken = overlayToken ? overlayToken : "";
    mOverlayTypeName = GetName();
    mOverlayClassLink.ListLinkAfter(&GlobalDebugOverlayClassList());
  }
} // namespace moho
