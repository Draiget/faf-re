#include "moho/ai/CAiTargetSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTarget.h"

using namespace moho;

namespace
{
  alignas(CAiTargetSerializer) unsigned char gCAiTargetSerializerStorage[sizeof(CAiTargetSerializer)];
  bool gCAiTargetSerializerConstructed = false;

  [[nodiscard]] CAiTargetSerializer* AcquireCAiTargetSerializer()
  {
    if (!gCAiTargetSerializerConstructed) {
      new (gCAiTargetSerializerStorage) CAiTargetSerializer();
      gCAiTargetSerializerConstructed = true;
    }

    return reinterpret_cast<CAiTargetSerializer*>(gCAiTargetSerializerStorage);
  }

  void cleanup_CAiTargetSerializer()
  {
    if (!gCAiTargetSerializerConstructed) {
      return;
    }

    AcquireCAiTargetSerializer()->~CAiTargetSerializer();
    gCAiTargetSerializerConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = CAiTarget::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTarget));
      CAiTarget::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E3540 (FUN_005E3540)
 *
 * What it does:
 * Lazily resolves CAiTarget RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiTargetSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiTargetType();
  const gpg::RType::load_func_t loadCallback = mLoadCallback ? mLoadCallback : &CAiTarget::DeserializeFromArchive;
  const gpg::RType::save_func_t saveCallback = mSaveCallback ? mSaveCallback : &CAiTarget::SerializeToArchive;
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = loadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = saveCallback;
}

/**
 * Address: 0x00BCEC50 (FUN_00BCEC50, register_CAiTargetSerializer)
 *
 * What it does:
 * Registers `CAiTarget` serializer callbacks and installs process-exit
 * cleanup.
 */
int moho::register_CAiTargetSerializer()
{
  CAiTargetSerializer* const serializer = AcquireCAiTargetSerializer();
  serializer->mHelperNext = nullptr;
  serializer->mHelperPrev = nullptr;
  serializer->mLoadCallback = &CAiTarget::DeserializeFromArchive;
  serializer->mSaveCallback = &CAiTarget::SerializeToArchive;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_CAiTargetSerializer);
}
