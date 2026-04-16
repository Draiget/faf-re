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
  bool gSAiReservedTransportBoneTypeInfoPreregistered = false;

  [[nodiscard]] SAiReservedTransportBoneTypeInfo* AcquireSAiReservedTransportBoneTypeInfo()
  {
    if (!gSAiReservedTransportBoneTypeInfoConstructed) {
      new (gSAiReservedTransportBoneTypeInfoStorage) SAiReservedTransportBoneTypeInfo();
      gSAiReservedTransportBoneTypeInfoConstructed = true;
    }

    return reinterpret_cast<SAiReservedTransportBoneTypeInfo*>(gSAiReservedTransportBoneTypeInfoStorage);
  }

  /**
   * Address: 0x005E3F60 (FUN_005E3F60)
   *
   * What it does:
   * Initializes the startup-owned `SAiReservedTransportBoneTypeInfo` instance
   * and preregisters RTTI for `SAiReservedTransportBone`.
   */
  [[nodiscard]] gpg::RType* preregister_SAiReservedTransportBoneTypeInfoStartup()
  {
    auto* const typeInfo = AcquireSAiReservedTransportBoneTypeInfo();
    if (!gSAiReservedTransportBoneTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(SAiReservedTransportBone), typeInfo);
      gSAiReservedTransportBoneTypeInfoPreregistered = true;
    }

    SAiReservedTransportBone::sType = typeInfo;
    return typeInfo;
  }

  void cleanup_SAiReservedTransportBoneTypeInfo()
  {
    if (!gSAiReservedTransportBoneTypeInfoConstructed) {
      return;
    }

    AcquireSAiReservedTransportBoneTypeInfo()->~SAiReservedTransportBoneTypeInfo();
    SAiReservedTransportBone::sType = nullptr;
    gSAiReservedTransportBoneTypeInfoConstructed = false;
    gSAiReservedTransportBoneTypeInfoPreregistered = false;
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
  (void)preregister_SAiReservedTransportBoneTypeInfoStartup();
  return std::atexit(&cleanup_SAiReservedTransportBoneTypeInfo);
}
