#include "moho/ai/SAttachPointTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(SAttachPointTypeInfo) unsigned char gSAttachPointTypeInfoStorage[sizeof(SAttachPointTypeInfo)];
  bool gSAttachPointTypeInfoConstructed = false;

  [[nodiscard]] SAttachPointTypeInfo* AcquireSAttachPointTypeInfo()
  {
    if (!gSAttachPointTypeInfoConstructed) {
      auto* const type = new (gSAttachPointTypeInfoStorage) SAttachPointTypeInfo();
      gpg::PreRegisterRType(typeid(SAttachPoint), type);
      gSAttachPointTypeInfoConstructed = true;
    }

    return reinterpret_cast<SAttachPointTypeInfo*>(gSAttachPointTypeInfoStorage);
  }

  void cleanup_SAttachPointTypeInfo()
  {
    if (!gSAttachPointTypeInfoConstructed) {
      return;
    }

    AcquireSAttachPointTypeInfo()->~SAttachPointTypeInfo();
    gSAttachPointTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E4230 (FUN_005E4230, scalar deleting thunk)
 */
SAttachPointTypeInfo::~SAttachPointTypeInfo() = default;

/**
 * Address: 0x005E4220 (FUN_005E4220, SAttachPointTypeInfo::GetName)
 */
const char* SAttachPointTypeInfo::GetName() const
{
  return "SAttachPoint";
}

/**
 * Address: 0x005E4200 (FUN_005E4200, SAttachPointTypeInfo::Init)
 */
void SAttachPointTypeInfo::Init()
{
  size_ = sizeof(SAttachPoint);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCEDD0 (FUN_00BCEDD0, register_SAttachPointTypeInfo)
 *
 * What it does:
 * Registers `SAttachPoint` type-info and installs process-exit cleanup.
 */
int moho::register_SAttachPointTypeInfo()
{
  (void)AcquireSAttachPointTypeInfo();
  return std::atexit(&cleanup_SAttachPointTypeInfo);
}

