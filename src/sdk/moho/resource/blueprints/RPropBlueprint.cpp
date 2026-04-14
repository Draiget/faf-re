#include "RPropBlueprint.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/RResId.h"

namespace moho
{
  gpg::RType* RPropBlueprint::sType = nullptr;

  /**
   * Address: 0x0051D250 (FUN_0051D250, ??0RPropBlueprint@Moho@@QAE@@Z)
   * Mangled: ??0RPropBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Runs base entity-blueprint construction and restores prop blueprint
   * display/defense/economy defaults.
   */
  RPropBlueprint::RPropBlueprint()
    : REntityBlueprint()
    , Display()
    , Defense()
    , Economy()
  {
    Display.MeshBlueprint.name.tidy(false, 0U);
    Display.UniformScale = 1.0f;
    Defense.MaxHealth = 1.0f;
    Defense.Health = 1.0f;
    Economy.ReclaimMassMax = 0.0f;
    Economy.ReclaimEnergyMax = 0.0f;
  }

  /**
   * Address: 0x0051D210 (FUN_0051D210)
   * Mangled: ?GetClass@RPropBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RPropBlueprint`.
   */
  gpg::RType* RPropBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RPropBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0051D230 (FUN_0051D230)
   * Mangled: ?GetDerivedObjectRef@RPropBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RPropBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0051D370 (FUN_0051D370)
   * Mangled: ?OnInitBlueprint@RPropBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Runs base entity-blueprint init and canonicalizes `Display.MeshBlueprint`
   * to a completed, lowercase, slash-normalized resource path.
   */
  void RPropBlueprint::OnInitBlueprint()
  {
    REntityBlueprint::OnInitBlueprint();

    msvc8::string completedMeshPath = RES_CompletePath(Display.MeshBlueprint.name.c_str(), mSource.c_str());
    gpg::STR_NormalizeFilenameLowerSlash(completedMeshPath);
    Display.MeshBlueprint.name.assign_owned(completedMeshPath.view());
  }
} // namespace moho
