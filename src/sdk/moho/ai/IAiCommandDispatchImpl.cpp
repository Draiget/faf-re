#include "moho/ai/IAiCommandDispatchImpl.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/unit/CUnitCommandQueue.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  class IAiCommandDispatchImplConstructed final : public IAiCommandDispatchImpl
  {
  public:
    int Execute() override
    {
      return static_cast<int>(TaskTick());
    }

    /**
     * Temporary concrete task-tick body used only for construct-time
     * instantiation until full `IAiCommandDispatchImpl::TaskTick` recovery is
     * landed in this lane.
     */
    ETaskStatus TaskTick() override
    {
      return static_cast<ETaskStatus>(1);
    }

    void OnEvent(EUnitCommandQueueStatus) override
    {}
  };

  static_assert(
    sizeof(IAiCommandDispatchImplConstructed) == sizeof(IAiCommandDispatchImpl),
    "IAiCommandDispatchImplConstructed size must match IAiCommandDispatchImpl"
  );

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandQueueType()
  {
    gpg::RType* type = CUnitCommandQueue::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CUnitCommandQueue));
      CUnitCommandQueue::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeDispatchObjectRef(IAiCommandDispatchImpl* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedIAiCommandDispatchImplType();
    return ref;
  }

  [[nodiscard]] CUnitCommandQueue* ReadCommandQueuePointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedCUnitCommandQueueType();
    if (!expectedType || !tracked.type) {
      return static_cast<CUnitCommandQueue*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<CUnitCommandQueue*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "CUnitCommandQueue",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  [[nodiscard]] gpg::RRef MakeCommandQueueRef(CUnitCommandQueue* const queue)
  {
    gpg::RRef out{};
    gpg::RType* const staticType = CachedCUnitCommandQueueType();
    out.mObj = nullptr;
    out.mType = staticType;
    if (!queue || !staticType) {
      out.mObj = queue;
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*queue));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!isDerived) {
      out.mObj = queue;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(queue) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }
} // namespace

gpg::RType* IAiCommandDispatchImpl::sType = nullptr;

/**
 * Address: 0x005990F0 (FUN_005990F0, scalar deleting thunk)
 */
IAiCommandDispatchImpl::~IAiCommandDispatchImpl() = default;

/**
 * Address: 0x00599330 (FUN_00599330, Moho::IAiCommandDispatchImpl::MemberConstruct)
 */
void IAiCommandDispatchImpl::MemberConstruct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }

  IAiCommandDispatchImpl* const object = new (std::nothrow) IAiCommandDispatchImplConstructed();
  result->SetUnowned(MakeDispatchObjectRef(object), 0u);
}

/**
 * Address: 0x00599C80 (FUN_00599C80, Moho::IAiCommandDispatchImpl::MemberDeserialize)
 */
void IAiCommandDispatchImpl::MemberDeserialize(gpg::ReadArchive* const archive, IAiCommandDispatchImpl* const object)
{
  if (!archive || !object) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(CachedCCommandTaskType(), object, ownerRef);

  bool state = false;
  archive->ReadBool(&state);
  object->mState = state ? 1u : 0u;

  object->mCommandQueue = ReadCommandQueuePointer(archive, ownerRef);
}

/**
 * Address: 0x00599CF0 (FUN_00599CF0, Moho::IAiCommandDispatchImpl::MemberSerialize)
 */
void IAiCommandDispatchImpl::MemberSerialize(const IAiCommandDispatchImpl* const object, gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(CachedCCommandTaskType(), object, ownerRef);
  archive->WriteBool(object && object->mState != 0u);

  const gpg::RRef queueRef = MakeCommandQueueRef(object ? object->mCommandQueue : nullptr);
  gpg::WriteRawPointer(archive, queueRef, gpg::TrackedPointerState::Unowned, ownerRef);
}
