#include "RBlueprint.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedStringType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::string));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIntType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  [[nodiscard]] gpg::RField* AddTypedField(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset
  )
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset));
    return &typeInfo->fields_.back();
  }
} // namespace

namespace moho
{
  gpg::RType* RBlueprint::sPointerType = nullptr;

  /**
   * Address: 0x0050DBA0 (FUN_0050DBA0)
   * Mangled: ?OnInitBlueprint@RBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Base blueprint post-load hook; default implementation is empty.
   */
  void RBlueprint::OnInitBlueprint() {}

  /**
   * Address: 0x0050DCF0 (FUN_0050DCF0, Moho::RBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers the base blueprint reflection fields and writes version/description
   * metadata for editor/runtime inspection lanes.
   */
  gpg::RField* RBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* field = AddTypedField(typeInfo, "BlueprintId", CachedStringType(), 0x08);
    field->v4 = 1;
    field->mDesc = "Blueprint Id";

    field = AddTypedField(typeInfo, "Description", CachedStringType(), 0x24);
    field->v4 = 3;
    field->mDesc = "Generic type of unit (non-display name)";

    field = AddTypedField(typeInfo, "Source", CachedStringType(), 0x40);
    field->v4 = 1;
    field->mDesc = "File this blueprint was defined in";

    return AddTypedField(typeInfo, "BlueprintOrdinal", CachedIntType(), 0x5C);
  }
} // namespace moho
