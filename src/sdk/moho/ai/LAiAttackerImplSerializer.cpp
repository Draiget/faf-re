#include "moho/ai/LAiAttackerImplSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/LAiAttackerImpl.h"

using namespace moho;

namespace
{
  struct LAiAttackerImplSerializationView
  {
    std::uint8_t pad_00[0x1C];
    CAiAttackerImpl* cImpl; // +0x1C
  };

  static_assert(offsetof(LAiAttackerImplSerializationView, cImpl) == 0x1C, "LAiAttackerImpl::cImpl offset must be 0x1C");
  static_assert(sizeof(LAiAttackerImplSerializationView) == 0x20, "LAiAttackerImplSerializationView size must be 0x20");

  alignas(LAiAttackerImplSerializer) unsigned char gLAiAttackerImplSerializerStorage[sizeof(LAiAttackerImplSerializer)];
  bool gLAiAttackerImplSerializerConstructed = false;

  [[nodiscard]] LAiAttackerImplSerializer* AcquireLAiAttackerImplSerializer()
  {
    if (!gLAiAttackerImplSerializerConstructed) {
      new (gLAiAttackerImplSerializerStorage) LAiAttackerImplSerializer();
      gLAiAttackerImplSerializerConstructed = true;
    }

    return reinterpret_cast<LAiAttackerImplSerializer*>(gLAiAttackerImplSerializerStorage);
  }

  template <typename T>
  [[nodiscard]] gpg::RRef MakeDerivedRef(T* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] gpg::RType* CachedCAiAttackerImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAiAttackerImpl));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedLAiAttackerImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LAiAttackerImpl));
    }
    return cached;
  }

  /**
   * Address: 0x00BF83D0 (FUN_00BF83D0, sub_BF83D0)
   *
   * What it does:
   * Tears down recovered static `LAiAttackerImplSerializer` storage.
   */
  void cleanup_LAiAttackerImplSerializer()
  {
    if (!gLAiAttackerImplSerializerConstructed) {
      return;
    }

    LAiAttackerImplSerializer* const serializer = AcquireLAiAttackerImplSerializer();
    if (serializer->mHelperNext != nullptr && serializer->mHelperPrev != nullptr) {
      serializer->mHelperNext->mPrev = serializer->mHelperPrev;
      serializer->mHelperPrev->mNext = serializer->mHelperNext;
    }
    serializer->mHelperNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
    serializer->mHelperPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
    serializer->~LAiAttackerImplSerializer();
    gLAiAttackerImplSerializerConstructed = false;
  }

  [[nodiscard]] LAiAttackerImpl* AsLAiAttackerImpl(const int objectPtr)
  {
    return reinterpret_cast<LAiAttackerImpl*>(static_cast<std::uintptr_t>(objectPtr));
  }

  [[nodiscard]] LAiAttackerImplSerializationView* AsView(LAiAttackerImpl* const task)
  {
    return reinterpret_cast<LAiAttackerImplSerializationView*>(task);
  }
} // namespace

/**
 * Address: 0x005D61A0 (FUN_005D61A0, Moho::LAiAttackerImplSerializer::Deserialize)
 *
 * What it does:
 * Restores the recovered `CAiAttackerImpl` link stored by `LAiAttackerImpl`.
 */
void LAiAttackerImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive) {
    return;
  }

  LAiAttackerImpl* const task = AsLAiAttackerImpl(objectPtr);
  if (!task) {
    return;
  }

  LAiAttackerImplSerializationView* const view = AsView(task);
  gpg::RRef owner{};
  gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, owner);
  if (!tracked.object) {
    view->cImpl = nullptr;
    return;
  }

  gpg::RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiAttackerImplType());
  if (upcast.mObj) {
    view->cImpl = static_cast<CAiAttackerImpl*>(upcast.mObj);
    return;
  }

  view->cImpl = static_cast<CAiAttackerImpl*>(tracked.object);
}

/**
 * Address: 0x005D61D0 (FUN_005D61D0, Moho::LAiAttackerImplSerializer::Serialize)
 *
 * What it does:
 * Saves the recovered `CAiAttackerImpl` link stored by `LAiAttackerImpl`.
 */
void LAiAttackerImplSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive) {
    return;
  }

  const LAiAttackerImpl* const task = AsLAiAttackerImpl(objectPtr);
  const LAiAttackerImplSerializationView* const view = reinterpret_cast<const LAiAttackerImplSerializationView*>(task);
  const gpg::RRef objectRef = MakeDerivedRef(view ? view->cImpl : nullptr, CachedCAiAttackerImplType());
  gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
}

/**
 * Address: 0x005DBF80 (FUN_005DBF80)
 *
 * What it does:
 * Lazily resolves `LAiAttackerImpl` RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void LAiAttackerImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedLAiAttackerImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE850 (FUN_00BCE850, register_LAiAttackerImplSerializer)
 *
 * What it does:
 * Registers `LAiAttackerImpl` serializer callbacks and installs process-exit
 * cleanup.
 */
void moho::register_LAiAttackerImplSerializer()
{
  LAiAttackerImplSerializer* const serializer = AcquireLAiAttackerImplSerializer();
  serializer->mHelperNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mHelperPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mLoadCallback = &LAiAttackerImplSerializer::Deserialize;
  serializer->mSaveCallback = &LAiAttackerImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_LAiAttackerImplSerializer);
}
