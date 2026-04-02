#include "moho/ai/SAiReservedTransportBoneTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/SAiReservedTransportBone.h"

using namespace moho;

gpg::RType* SAiReservedTransportBone::sType = nullptr;

namespace
{
  alignas(SAiReservedTransportBoneTypeInfo)
    unsigned char gSAiReservedTransportBoneTypeInfoStorage[sizeof(SAiReservedTransportBoneTypeInfo)];
  bool gSAiReservedTransportBoneTypeInfoConstructed = false;

  [[nodiscard]] SAiReservedTransportBoneTypeInfo* AcquireSAiReservedTransportBoneTypeInfo()
  {
    if (!gSAiReservedTransportBoneTypeInfoConstructed) {
      auto* const type = new (gSAiReservedTransportBoneTypeInfoStorage) SAiReservedTransportBoneTypeInfo();
      gpg::PreRegisterRType(typeid(SAiReservedTransportBone), type);
      SAiReservedTransportBone::sType = type;
      gSAiReservedTransportBoneTypeInfoConstructed = true;
    }

    return reinterpret_cast<SAiReservedTransportBoneTypeInfo*>(gSAiReservedTransportBoneTypeInfoStorage);
  }

  void cleanup_SAiReservedTransportBoneTypeInfo()
  {
    if (!gSAiReservedTransportBoneTypeInfoConstructed) {
      return;
    }

    AcquireSAiReservedTransportBoneTypeInfo()->~SAiReservedTransportBoneTypeInfo();
    SAiReservedTransportBone::sType = nullptr;
    gSAiReservedTransportBoneTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E3FF0 (FUN_005E3FF0, scalar deleting thunk)
 */
SAiReservedTransportBoneTypeInfo::~SAiReservedTransportBoneTypeInfo() = default;

/**
 * Address: 0x005E3FE0 (FUN_005E3FE0, ?GetName@SAiReservedTransportBoneTypeInfo@Moho@@UBEPBDXZ)
 */
const char* SAiReservedTransportBoneTypeInfo::GetName() const
{
  return "SAiReservedTransportBone";
}

/**
 * Address: 0x005E3FC0 (FUN_005E3FC0, ?Init@SAiReservedTransportBoneTypeInfo@Moho@@UAEXXZ)
 */
void SAiReservedTransportBoneTypeInfo::Init()
{
  size_ = sizeof(SAiReservedTransportBone);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCED70 (FUN_00BCED70, register_SAiReservedTransportBoneTypeInfo)
 *
 * What it does:
 * Registers `SAiReservedTransportBone` type-info and installs process-exit
 * cleanup.
 */
int moho::register_SAiReservedTransportBoneTypeInfo()
{
  (void)AcquireSAiReservedTransportBoneTypeInfo();
  return std::atexit(&cleanup_SAiReservedTransportBoneTypeInfo);
}
