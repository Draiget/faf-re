#include "ArchiveSerialization.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/sim/CWldSession.h"
#include "ReadArchive.h"
#include "String.h"
#include "WriteArchive.h"

using namespace gpg;

namespace
{
  [[noreturn]] void ThrowSerializationError(const char* const message)
  {
    throw SerializationError(message ? message : "");
  }

  [[noreturn]] void ThrowSerializationError(const msvc8::string& message)
  {
    throw SerializationError(message.c_str());
  }

  const char* SafeTypeName(const RType* const type)
  {
    return type ? type->GetName() : "null";
  }

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  [[nodiscard]] gpg::RType* CachedLaunchInfoBaseType()
  {
    gpg::RType* type = moho::LaunchInfoBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::LaunchInfoBase));
      moho::LaunchInfoBase::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSessionSaveDataType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::SSessionSaveData));
    }
    return sType;
  }

  [[nodiscard]] bool IsPointerCompatibleWithExpectedType(
    const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType
  )
  {
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return upcast.mObj != nullptr;
  }

  void PromoteTrackedPointerToShared(gpg::TrackedPointerInfo& tracked)
  {
    GPG_ASSERT(tracked.type != nullptr);
    GPG_ASSERT(tracked.type != nullptr && tracked.type->deleteFunc_ != nullptr);
    if (!tracked.type || !tracked.type->deleteFunc_) {
      ThrowSerializationError("Ownership conflict while loading archive");
    }

    auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
      tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
    );

    tracked.sharedObject = tracked.object;
    tracked.sharedControl = control;
    tracked.state = gpg::TrackedPointerState::Shared;
  }

  void EnsureTrackedPointerSharedOwnership(gpg::TrackedPointerInfo& tracked)
  {
    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      PromoteTrackedPointerToShared(tracked);
      return;
    }

    if (tracked.state != gpg::TrackedPointerState::Shared) {
      ThrowSerializationError("Ownership conflict while loading archive");
    }

    if (!tracked.sharedObject || !tracked.sharedControl) {
      ThrowSerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }
  }

  [[noreturn]]
  void ThrowTypeMismatch(const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType)
  {
    const char* const expectedName = expectedType ? expectedType->GetName() : "LaunchInfoBase";
    const char* const actualName = tracked.type ? tracked.type->GetName() : "null";

    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "LaunchInfoBase",
      actualName ? actualName : "null"
    ));
  }

  template <class T>
  void AssignRetainedRawSharedPointer(
    boost::SharedPtrRaw<T>& outPointer, const gpg::TrackedPointerInfo& tracked
  )
  {
    boost::SharedPtrRaw<T> source{};
    source.px = static_cast<T*>(tracked.sharedObject);
    source.pi = tracked.sharedControl;
    outPointer.assign_retain(source);
  }
} // namespace

/**
 * Address: 0x00953320 (FUN_00953320)
 * Demangled: gpg::WriteArchive::WriteRawPointer
 *
 * What it does:
 * Writes tracked-pointer token payload and serializes newly seen pointees.
 */
void gpg::WriteRawPointer(
  WriteArchive* const archive, const RRef& objectRef, const TrackedPointerState state, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error while creating archive: null WriteArchive.");
  }

  if (!objectRef.mObj) {
    archive->WriteMarker(static_cast<int>(ArchiveToken::NullPointer));
    return;
  }

  std::map<const void*, WriteArchive::TrackedPointerRecord>::iterator it = archive->mObjRefs.find(objectRef.mObj);
  WriteArchive::TrackedPointerRecord* record = nullptr;

  if (it == archive->mObjRefs.end()) {
    WriteArchive::TrackedPointerRecord fresh{};
    fresh.type = objectRef.mType;
    fresh.index = static_cast<int>(archive->mObjRefs.size());
    fresh.ownership = TrackedPointerState::Reserved;

    const std::pair<std::map<const void*, WriteArchive::TrackedPointerRecord>::iterator, bool> inserted =
      archive->mObjRefs.insert(std::make_pair(objectRef.mObj, fresh));
    record = &inserted.first->second;

    archive->WriteMarker(static_cast<int>(ArchiveToken::NewObject));
    archive->WriteRefCounts(objectRef.mType);

    if (!objectRef.mType || !objectRef.mType->serSaveFunc_) {
      ThrowSerializationError(STR_Printf(
        "Error while creating archive: encounted an object of type \"%s\", but we don't have a save function for it.",
        SafeTypeName(objectRef.mType)
      ));
    }

    objectRef.mType->serSaveFunc_(
      archive, reinterpret_cast<int>(objectRef.mObj), objectRef.mType->version_, const_cast<RRef*>(&ownerRef)
    );

    if (record->ownership == TrackedPointerState::Reserved) {
      record->ownership = TrackedPointerState::Unowned;
    }

    archive->WriteMarker(static_cast<int>(ArchiveToken::ObjectTerminator));
  } else {
    record = &it->second;
    if (record->ownership == TrackedPointerState::Reserved) {
      ThrowSerializationError(
        "Error while creating archive: recursively encountered a pointer to an object for which construction data is "
        "still being written"
      );
    }

    archive->WriteMarker(static_cast<int>(ArchiveToken::ExistingPointer));
    archive->WriteInt(record->index);
  }

  if (state == TrackedPointerState::Owned) {
    if (record->ownership != TrackedPointerState::Unowned) {
      ThrowSerializationError("Ownership conflict while writing archive.");
    }
    record->ownership = TrackedPointerState::Owned;
  } else if (state == TrackedPointerState::Shared) {
    if (record->ownership == TrackedPointerState::Owned) {
      ThrowSerializationError("Shared/owned conflict while writing archive.");
    }
    record->ownership = TrackedPointerState::Shared;
  }
}

/**
 * Address: 0x00953720 (FUN_00953720)
 * Demangled: gpg::ReadArchive::ReadRawPointer
 *
 * What it does:
 * Reads pointer token payload and resolves a tracked pointer reference.
 */
TrackedPointerInfo& gpg::ReadRawPointer(ReadArchive* const archive, const RRef& ownerRef)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  const ArchiveToken token = static_cast<ArchiveToken>(archive->NextMarker());
  if (token == ArchiveToken::NullPointer) {
    archive->mNullTrackedPointer = {};
    return archive->mNullTrackedPointer;
  }

  if (token == ArchiveToken::ExistingPointer) {
    int index = -1;
    archive->ReadInt(&index);

    if (index < 0 || static_cast<size_t>(index) >= archive->mTrackedPtrs.size()) {
      ThrowSerializationError(STR_Printf(
        "Error detected in archive: found a reference to an existing pointer of index %d, but only %d pointers have "
        "been created.",
        index,
        static_cast<int>(archive->mTrackedPtrs.size())
      ));
    }

    TrackedPointerInfo& tracked = archive->mTrackedPtrs[static_cast<size_t>(index)];
    if (tracked.state == TrackedPointerState::Reserved) {
      ThrowSerializationError(
        "Error detected in archive: found a reference to an existing pointer that has not been constructed yet."
      );
    }
    return tracked;
  }

  if (token != ArchiveToken::NewObject) {
    ThrowSerializationError(
      STR_Printf("Error detected in archive: found an invalid token value of %d", static_cast<int>(token))
    );
  }

  const TypeHandle handle = archive->ReadTypeHandle();
  if (!handle.type) {
    ThrowSerializationError("Error detected in archive: null type handle.");
  }

  if (!handle.type->newRefFunc_) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found a pointer to an object of type \"%s\", but we don't have a constructor for it.",
      SafeTypeName(handle.type)
    ));
  }

  const RRef objectRef = handle.type->newRefFunc_();
  TrackedPointerInfo tracked{};
  tracked.object = objectRef.mObj;
  tracked.type = objectRef.mType ? objectRef.mType : handle.type;
  tracked.state = TrackedPointerState::Reserved;
  tracked.sharedObject = nullptr;
  tracked.sharedControl = nullptr;

  const size_t trackedIndex = archive->mTrackedPtrs.size();
  archive->mTrackedPtrs.push_back(tracked);

  RType* const loadedType = archive->mTrackedPtrs[trackedIndex].type;
  void* const loadedObject = archive->mTrackedPtrs[trackedIndex].object;
  if (!loadedType || !loadedType->serLoadFunc_) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but we don't have a loader for it.",
      SafeTypeName(loadedType)
    ));
  }

  loadedType->serLoadFunc_(archive, reinterpret_cast<int>(loadedObject), handle.version, const_cast<RRef*>(&ownerRef));

  TrackedPointerInfo& trackedRef = archive->mTrackedPtrs[trackedIndex];

  if (archive->NextMarker() != static_cast<int>(ArchiveToken::ObjectTerminator)) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: data for object of type \"%s\" did not terminate properly.",
      SafeTypeName(trackedRef.type)
    ));
  }

  if (trackedRef.state == TrackedPointerState::Reserved) {
    trackedRef.state = TrackedPointerState::Unowned;
  }

  return trackedRef;
}

/**
 * Address: 0x00884C90 (FUN_00884C90)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<LaunchInfoBase>`,
 * promotes unowned entries to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_LaunchInfoBase(
  boost::SharedPtrRaw<moho::LaunchInfoBase>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedLaunchInfoBaseType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}

/**
 * Address: 0x008843F0 (FUN_008843F0)
 *
 * What it does:
 * Reads one tracked pointer lane as `boost::shared_ptr<SSessionSaveData>`,
 * promotes unowned entries to shared ownership, and validates pointee type.
 */
void gpg::ReadPointerShared_SSessionSaveData(
  boost::SharedPtrRaw<moho::SSessionSaveData>& outPointer, ReadArchive* const archive, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  TrackedPointerInfo& tracked = ReadRawPointer(archive, ownerRef);
  if (!tracked.object) {
    outPointer.release();
    return;
  }

  EnsureTrackedPointerSharedOwnership(tracked);

  gpg::RType* const expectedType = CachedSessionSaveDataType();
  if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
    ThrowTypeMismatch(tracked, expectedType);
  }

  AssignRetainedRawSharedPointer(outPointer, tracked);
}
