#include "moho/ai/CAiBrainTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"
#include "moho/script/CScriptObject.h"

using namespace moho;

namespace
{
  alignas(CAiBrainTypeInfo) unsigned char gCAiBrainTypeInfoStorage[sizeof(CAiBrainTypeInfo)];
  bool gCAiBrainTypeInfoConstructed = false;

  [[nodiscard]] CAiBrainTypeInfo& AcquireCAiBrainTypeInfo()
  {
    if (!gCAiBrainTypeInfoConstructed) {
      new (gCAiBrainTypeInfoStorage) CAiBrainTypeInfo();
      gCAiBrainTypeInfoConstructed = true;
    }

    return *reinterpret_cast<CAiBrainTypeInfo*>(gCAiBrainTypeInfoStorage);
  }

  [[nodiscard]] CAiBrainTypeInfo* PeekCAiBrainTypeInfo() noexcept
  {
    if (!gCAiBrainTypeInfoConstructed) {
      return nullptr;
    }

    return reinterpret_cast<CAiBrainTypeInfo*>(gCAiBrainTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  void cleanup_CAiBrainTypeInfoStartup()
  {
    CAiBrainTypeInfo* const typeInfo = PeekCAiBrainTypeInfo();
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CAiBrainTypeInfoStartupBootstrap
  {
    CAiBrainTypeInfoStartupBootstrap()
    {
      moho::register_CAiBrainTypeInfoStartup();
    }
  };

  CAiBrainTypeInfoStartupBootstrap gCAiBrainTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x00579BB0 (FUN_00579BB0, scalar deleting thunk)
 */
CAiBrainTypeInfo::~CAiBrainTypeInfo() = default;

/**
 * Address: 0x00579BA0 (FUN_00579BA0, ?GetName@CAiBrainTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiBrainTypeInfo::GetName() const
{
  return "CAiBrain";
}

/**
 * Address: 0x00579B80 (FUN_00579B80, ?Init@CAiBrainTypeInfo@Moho@@UAEXXZ)
 */
void CAiBrainTypeInfo::Init()
{
  size_ = sizeof(CAiBrain);
  gpg::RType::Init();

  gpg::RField baseField{};
  baseField.mName = CachedCScriptObjectType()->GetName();
  baseField.mType = CachedCScriptObjectType();
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}

/**
 * Address: 0x00BCB3D0 (FUN_00BCB3D0, register_Moho::CAiBrainTypeInfo)
 *
 * What it does:
 * Ensures startup construction of `CAiBrainTypeInfo` and installs process-exit cleanup.
 */
void moho::register_CAiBrainTypeInfoStartup()
{
  (void)AcquireCAiBrainTypeInfo();
  (void)std::atexit(&cleanup_CAiBrainTypeInfoStartup);
}
