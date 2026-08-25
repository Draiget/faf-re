#include "moho/ai/LAiAttackerImplSerializer.h"

#include <cstdint>
#include <cstdlib>
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

  // Address: 0x010B0358 -- process-global `LAiAttackerImplSerializer`
  // singleton. Constructing it runs LAiAttackerImplSerializer::
  // LAiAttackerImplSerializer() (0x00BCE850), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers and explicitly registers this
  // translation unit's unlink callback via `atexit` (this class has no
  // user-declared destructor).
  LAiAttackerImplSerializer gLAiAttackerImplSerializer;

  /**
   * Address: 0x00BF83D0 (FUN_00BF83D0, sub_BF83D0)
   *
   * What it does:
   * Unlinks the global `LAiAttackerImplSerializer` helper node from the
   * intrusive serializer chain and restores it to a self-linked node.
   * Registered by the real dynamic initializer (0x00BCE850) as the global's
   * `atexit` teardown.
   */
  void CleanupLAiAttackerImplSerializer()
  {
    gLAiAttackerImplSerializer.ResetLinks();
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
 * Address: 0x00BCE850 (FUN_00BCE850, dynamic initializer for the global
 * `LAiAttackerImplSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the load/save callback fields, and explicitly
 * registers `atexit` cleanup.
 */
LAiAttackerImplSerializer::LAiAttackerImplSerializer()
  : mLoadCallback(&LAiAttackerImplSerializer::Deserialize)
  , mSaveCallback(&LAiAttackerImplSerializer::Serialize)
{
  (void)std::atexit(&CleanupLAiAttackerImplSerializer);
}

/**
 * Address: 0x005DBF80 (FUN_005DBF80)
 *
 * What it does:
 * Lazily resolves `LAiAttackerImpl` RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void LAiAttackerImplSerializer::Init()
{
  gpg::RType* const type = CachedLAiAttackerImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE850 caller lane (`CAiAttackerImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `LAiAttackerImplSerializer` singleton from an explicit registration
 * sequence. `gLAiAttackerImplSerializer` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiAttackerImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
void moho::register_LAiAttackerImplSerializer()
{
}
