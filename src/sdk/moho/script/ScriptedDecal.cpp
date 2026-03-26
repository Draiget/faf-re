#include "moho/script/ScriptedDecal.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

using namespace moho;

namespace
{
  struct RuntimeDecalEntryView
  {
    std::uint32_t mReserved0;
    Broadcaster mLink;
  };

  constexpr std::uintptr_t kDeletedRuntimeLinkTag = 0x4;

  [[nodiscard]] gpg::RType* CachedScriptedDecalType()
  {
    if (!ScriptedDecal::sType) {
      ScriptedDecal::sType = gpg::LookupRType(typeid(ScriptedDecal));
    }
    return ScriptedDecal::sType;
  }

  [[nodiscard]] gpg::RRef MakeScriptedDecalRef(ScriptedDecal* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedScriptedDecalType();
    return ref;
  }

  [[nodiscard]] RuntimeDecalEntryView* RuntimeEntryFromLink(TDatListItem<Broadcaster, void>* link) noexcept
  {
    if (!link) {
      return nullptr;
    }

    const auto linkAddress = reinterpret_cast<std::uintptr_t>(link);
    if (linkAddress == kDeletedRuntimeLinkTag) {
      return nullptr;
    }

    return reinterpret_cast<RuntimeDecalEntryView*>(linkAddress - offsetof(RuntimeDecalEntryView, mLink));
  }
} // namespace

gpg::RType* ScriptedDecal::sType = nullptr;

/**
 * Address: 0x0087EC20 (FUN_0087EC20, non-deleting body)
 */
ScriptedDecal::~ScriptedDecal()
{
  RuntimeDecalEntryView* const runtimeEntry = RuntimeEntryFromLink(mRuntimeLink.mPrev);
  if (runtimeEntry && mDecalService) {
    mDecalService->RemoveRuntimeDecal(runtimeEntry);
  }

  mRuntimeLink.ListUnlink();
}

/**
 * Address: 0x0087F030 (FUN_0087F030, ?GetClass@ScriptedDecal@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* ScriptedDecal::GetClass() const
{
  return CachedScriptedDecalType();
}

/**
 * Address: 0x0087F050 (FUN_0087F050, ?GetDerivedObjectRef@ScriptedDecal@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef ScriptedDecal::GetDerivedObjectRef()
{
  return MakeScriptedDecalRef(this);
}
