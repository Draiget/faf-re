#include "RPropBlueprint.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  namespace
  {
    [[nodiscard]] std::string
    CompleteResourcePath(const std::string_view sourceName, const std::string_view resourceName)
    {
      if (resourceName.empty()) {
        return {};
      }

      std::filesystem::path resourcePath{resourceName};
      if (!resourcePath.is_absolute() && !sourceName.empty()) {
        const std::filesystem::path sourcePath{sourceName};
        resourcePath = sourcePath.parent_path() / resourcePath;
      }

      return resourcePath.lexically_normal().generic_string();
    }

  } // namespace

  gpg::RType* RPropBlueprint::sType = nullptr;

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

    std::string completedMeshPath = CompleteResourcePath(mSource.view(), Display.MeshBlueprint.name.view());
    gpg::STR_NormalizeFilenameLowerSlash(completedMeshPath);
    Display.MeshBlueprint.name.assign_owned(completedMeshPath);
  }
} // namespace moho
