
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/LAiAttackerImpl.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{
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

} // namespace

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<LAiAttackerImpl>::Deserialize` 0x005D61A0.
   */
  void LAiAttackerImpl::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }


    gpg::RRef owner{};
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      cImpl = nullptr;
      return;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAiAttackerImplType());
    if (upcast.mObj) {
      cImpl = static_cast<CAiAttackerImpl*>(upcast.mObj);
      return;
    }

    cImpl = static_cast<CAiAttackerImpl*>(tracked.object);
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<LAiAttackerImpl>::Serialize` 0x005D61D0.
   */
  void LAiAttackerImpl::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef objectRef = MakeDerivedRef(this ? cImpl : nullptr, CachedCAiAttackerImplType());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<LAiAttackerImpl>`, vtable 0x00E1EAC4.
   *
   * Address: 0x00BCE850 (FUN_00BCE850 -- constructs the global and registers its destructor.)
   * Address: 0x00BF83D0 (FUN_00BF83D0 -- the global's destructor.)
   * Address: 0x005DBF80 (FUN_005DBF80 -- `Init`.)
   * Address: 0x005D61A0 (FUN_005D61A0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x005D61D0 (FUN_005D61D0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct LAiAttackerImplSerializer : gpg::SerSaveLoadHelper<LAiAttackerImpl>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B0358 -- process-global `LAiAttackerImplSerializer` singleton.
  moho::LAiAttackerImplSerializer gLAiAttackerImplSerializer;
} // namespace
