#include "moho/script/ScriptedDecalTypeInfo.h"

#include <typeinfo>

#include "moho/script/ScriptedDecal.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x0087F180 (FUN_0087F180, ScriptedDecalTypeInfo::AddBase_CScriptObject)
   *
   * What it does:
   * Registers CScriptObject as reflected base at zero offset.
   */
  void AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = CScriptObject::StaticGetClass();
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CScriptObject));
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x0087F130 (FUN_0087F130, scalar deleting thunk)
 */
ScriptedDecalTypeInfo::~ScriptedDecalTypeInfo() = default;

/**
 * Address: 0x0087F120 (FUN_0087F120, ?GetName@ScriptedDecalTypeInfo@Moho@@UBEPBDXZ)
 */
const char* ScriptedDecalTypeInfo::GetName() const
{
  return "ScriptedDecal";
}

/**
 * Address: 0x0087F0F0 (FUN_0087F0F0, ?Init@ScriptedDecalTypeInfo@Moho@@UAEXXZ)
 */
void ScriptedDecalTypeInfo::Init()
{
  size_ = sizeof(ScriptedDecal);
  AddBase_CScriptObject(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0087F090 (FUN_0087F090, preregister_ScriptedDecalTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `moho::ScriptedDecal`.
 */
[[nodiscard]] gpg::RType* preregister_ScriptedDecalTypeInfo()
{
  static ScriptedDecalTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(ScriptedDecal), &typeInfo);
  return &typeInfo;
}
