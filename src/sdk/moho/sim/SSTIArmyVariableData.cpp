#include "SSTIArmyVariableData.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
  [[nodiscard]] int PointerToArchiveInt(const void* ptr)
  {
    return static_cast<int>(reinterpret_cast<std::uintptr_t>(ptr));
  }

  [[nodiscard]] gpg::RType* FindRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::TypeMap& map = gpg::GetRTypeMap();
    for (const char* name : names) {
      if (!name || !*name) {
        continue;
      }

      const auto it = map.find(name);
      if (it != map.end()) {
        return it->second;
      }

      for (auto jt = map.begin(); jt != map.end(); ++jt) {
        const char* registeredName = jt->first;
        if (registeredName && std::strstr(registeredName, name) != nullptr) {
          return jt->second;
        }
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* RequireRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::RType* type = FindRTypeByNameAny(names);
    GPG_ASSERT(type != nullptr);
    return type;
  }

  void DeserializeObjectByRTypeName(
    gpg::ReadArchive* archive, void* object, const std::initializer_list<const char*>& typeNames, gpg::RRef* ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serLoadFunc_ != nullptr);
    type->serLoadFunc_(archive, PointerToArchiveInt(object), type->version_, ownerRef);
  }

  void SerializeObjectByRTypeName(
    gpg::WriteArchive* archive,
    const void* object,
    const std::initializer_list<const char*>& typeNames,
    gpg::RRef* ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serSaveFunc_ != nullptr);
    type->serSaveFunc_(archive, PointerToArchiveInt(object), type->version_, ownerRef);
  }

  alignas(moho::SSTIArmyVariableDataTypeInfo)
    unsigned char gSSTIArmyVariableDataTypeInfoStorage[sizeof(moho::SSTIArmyVariableDataTypeInfo)]{};
  bool gSSTIArmyVariableDataTypeInfoConstructed = false;

  [[nodiscard]] moho::SSTIArmyVariableDataTypeInfo& AcquireSSTIArmyVariableDataTypeInfo()
  {
    if (!gSSTIArmyVariableDataTypeInfoConstructed) {
      new (gSSTIArmyVariableDataTypeInfoStorage) moho::SSTIArmyVariableDataTypeInfo();
      gSSTIArmyVariableDataTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::SSTIArmyVariableDataTypeInfo*>(gSSTIArmyVariableDataTypeInfoStorage);
  }

  void CleanupSSTIArmyVariableDataTypeInfoAtexit()
  {
    if (!gSSTIArmyVariableDataTypeInfoConstructed) {
      return;
    }

    AcquireSSTIArmyVariableDataTypeInfo().~SSTIArmyVariableDataTypeInfo();
    gSSTIArmyVariableDataTypeInfoConstructed = false;
  }

  moho::SSTIArmyVariableDataSerializer gSSTIArmyVariableDataSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::SerHelperBase* ResetSSTIArmyVariableDataSerializerHelperLinks() noexcept
  {
    gSSTIArmyVariableDataSerializer.mHelperNext->mPrev = gSSTIArmyVariableDataSerializer.mHelperPrev;
    gSSTIArmyVariableDataSerializer.mHelperPrev->mNext = gSSTIArmyVariableDataSerializer.mHelperNext;
    gpg::SerHelperBase* const self = HelperSelfNode(gSSTIArmyVariableDataSerializer);
    gSSTIArmyVariableDataSerializer.mHelperPrev = self;
    gSSTIArmyVariableDataSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00550A60 (FUN_00550A60)
   *
   * What it does:
   * Unlinks `SSTIArmyVariableDataSerializer` helper node from the intrusive
   * helper list and restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTIArmyVariableDataSerializerHelperNodePrimary() noexcept
  {
    return ResetSSTIArmyVariableDataSerializerHelperLinks();
  }

  /**
   * Address: 0x00550A90 (FUN_00550A90)
   *
   * What it does:
   * Secondary entrypoint for `SSTIArmyVariableDataSerializer` helper-node
   * unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSSTIArmyVariableDataSerializerHelperNodeSecondary() noexcept
  {
    return ResetSSTIArmyVariableDataSerializerHelperLinks();
  }

  void CleanupSSTIArmyVariableDataSerializerAtexit()
  {
    (void)CleanupSSTIArmyVariableDataSerializerHelperNodePrimary();
  }

  /**
   * Address: 0x00704250 (FUN_00704250)
   *
   * What it does:
   * Copies one contiguous 32-bit range `[sourceBegin, sourceEnd)` into
   * destination storage and returns one-past the last written slot.
   */
  [[maybe_unused]] std::uint32_t* CopyWordRangeForward(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destination = *sourceBegin;
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x00550F20 (FUN_00550F20, j_Moho::SSTIArmyVariableData::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `SSTIArmyVariableData::SerializeLoadBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberDeserializeThunk(
    moho::SSTIArmyVariableData* const data, gpg::ReadArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeLoadBody(archive, nullptr);
  }

  /**
   * Address: 0x00550F30 (FUN_00550F30, j_Moho::SSTIArmyVariableData::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `SSTIArmyVariableData::SerializeSaveBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberSerializeThunk(
    const moho::SSTIArmyVariableData* const data, gpg::WriteArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeSaveBody(archive, nullptr);
  }

  /**
   * Address: 0x00550F80 (FUN_00550F80, j_Moho::SSTIArmyVariableData::MemberDeserialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `SSTIArmyVariableData::SerializeLoadBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberDeserializeThunkSecondary(
    moho::SSTIArmyVariableData* const data, gpg::ReadArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeLoadBody(archive, nullptr);
  }

  /**
   * Address: 0x00550F90 (FUN_00550F90, j_Moho::SSTIArmyVariableData::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `SSTIArmyVariableData::SerializeSaveBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberSerializeThunkSecondary(
    const moho::SSTIArmyVariableData* const data, gpg::WriteArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeSaveBody(archive, nullptr);
  }

  /**
   * Address: 0x00700280 (FUN_00700280)
   *
   * What it does:
   * Assigns one `SSTIArmyVariableData` payload from `source` into
   * `destination` and returns the destination pointer.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* AssignSSTIArmyVariableData(
    const moho::SSTIArmyVariableData* const source,
    moho::SSTIArmyVariableData* const destination
  )
  {
    *destination = *source;
    return destination;
  }

  struct SSTIArmyVariableDataOwnerSlotRuntime
  {
    std::uint8_t reserved00_7F[0x80]{};
    moho::SSTIArmyVariableData variableData;
  };
  static_assert(
    offsetof(SSTIArmyVariableDataOwnerSlotRuntime, variableData) == 0x80,
    "SSTIArmyVariableDataOwnerSlotRuntime::variableData offset must be 0x80"
  );

  /**
   * Address: 0x008B17D0 (FUN_008B17D0)
   *
   * What it does:
   * Copies one source `SSTIArmyVariableData` payload into an owning object's
   * embedded variable-data slot at offset `+0x80`.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* AssignSSTIArmyVariableDataIntoEmbeddedOwnerSlot(
    const moho::SSTIArmyVariableData* const source,
    SSTIArmyVariableDataOwnerSlotRuntime* const owner
  )
  {
    return AssignSSTIArmyVariableData(source, &owner->variableData);
  }

  /**
   * Address: 0x007519A0 (FUN_007519A0)
   *
   * What it does:
   * Copies one contiguous `SSTIArmyVariableData` assignment range
   * `[sourceBegin, sourceEnd)` into `destinationBegin` and returns the end of
   * the destination range.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeForwardAssign(
    const moho::SSTIArmyVariableData* sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd,
    moho::SSTIArmyVariableData* destinationBegin
  )
  {
    moho::SSTIArmyVariableData* destinationCursor = destinationBegin;
    for (const moho::SSTIArmyVariableData* sourceCursor = sourceBegin;
         sourceCursor != sourceEnd;
         ++sourceCursor, ++destinationCursor) {
      (void)AssignSSTIArmyVariableData(sourceCursor, destinationCursor);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x00753C80 (FUN_00753C80)
   *
   * What it does:
   * Alternate call-convention lane that forwards one contiguous
   * `SSTIArmyVariableData` assignment copy from `[sourceBegin, sourceEnd)` into
   * destination storage and returns destination end.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeForwardAssignThunkA(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    return CopySSTIArmyVariableDataRangeForwardAssign(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00751A00 (FUN_00751A00)
   *
   * What it does:
   * Assign-fills one destination range `[destinationBegin, destinationEnd)`
   * from a single source payload and returns the last written destination slot
   * (or `destinationBegin` when the range is empty).
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* FillSSTIArmyVariableDataRangeAssignReturnLastWritten(
    moho::SSTIArmyVariableData* const destinationBegin,
    moho::SSTIArmyVariableData* const destinationEnd,
    const moho::SSTIArmyVariableData* const source
  )
  {
    moho::SSTIArmyVariableData* lastWritten = destinationBegin;
    for (moho::SSTIArmyVariableData* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
      lastWritten = AssignSSTIArmyVariableData(source, cursor);
    }

    return lastWritten;
  }

  /**
   * Address: 0x00753CE0 (FUN_00753CE0)
   *
   * What it does:
   * Alternate lane that assign-fills one destination range
   * `[destinationBegin, destinationEnd)` from one source payload and returns
   * the last written destination slot.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* FillSSTIArmyVariableDataRangeAssignReturnLastWrittenThunkA(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const source,
    moho::SSTIArmyVariableData* const destinationEnd
  )
  {
    return FillSSTIArmyVariableDataRangeAssignReturnLastWritten(destinationBegin, destinationEnd, source);
  }

  /**
   * Address: 0x00751A20 (FUN_00751A20)
   *
   * What it does:
   * Copies one contiguous `SSTIArmyVariableData` assignment range backward from
   * `[sourceBegin, sourceEnd)` into destination storage ending at
   * `destinationEnd`, and returns the begin of the written destination range.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeBackwardAssign(
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* sourceEnd,
    moho::SSTIArmyVariableData* destinationEnd
  )
  {
    moho::SSTIArmyVariableData* destinationCursor = destinationEnd;
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationCursor;
      (void)AssignSSTIArmyVariableData(sourceEnd, destinationCursor);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x00753D00 (FUN_00753D00)
   *
   * What it does:
   * Alternate call-convention lane that backward-copies
   * `[sourceBegin, sourceEnd)` into destination storage ending at
   * `destinationEnd`.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeBackwardAssignThunkA(
    const moho::SSTIArmyVariableData* const sourceEnd,
    moho::SSTIArmyVariableData* const destinationEnd,
    const moho::SSTIArmyVariableData* const sourceBegin
  )
  {
    return CopySSTIArmyVariableDataRangeBackwardAssign(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x00755920 (FUN_00755920)
   *
   * What it does:
   * Secondary backward-copy lane for `SSTIArmyVariableData` assignment ranges.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeBackwardAssignThunkB(
    moho::SSTIArmyVariableData* const destinationEnd,
    const moho::SSTIArmyVariableData* const sourceEnd,
    const moho::SSTIArmyVariableData* const sourceBegin
  )
  {
    return CopySSTIArmyVariableDataRangeBackwardAssign(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x005632D0 (FUN_005632D0, copy_SSTIArmyVariableData_range_with_rollback)
   *
   * What it does:
   * Copy-constructs one contiguous `SSTIArmyVariableData` range into
   * destination storage and destroys already-constructed elements before
   * rethrowing if a construction step throws.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeWithRollback(
    const moho::SSTIArmyVariableData* sourceBegin,
    const moho::SSTIArmyVariableData* sourceEnd,
    moho::SSTIArmyVariableData* destinationBegin
  )
  {
    moho::SSTIArmyVariableData* destinationCursor = destinationBegin;
    try {
      for (const moho::SSTIArmyVariableData* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          ::new (destinationCursor) moho::SSTIArmyVariableData(*sourceCursor);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (moho::SSTIArmyVariableData* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->~SSTIArmyVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x00562620 (FUN_00562620)
   *
   * What it does:
   * Register-shape adapter for guarded contiguous
   * `SSTIArmyVariableData` copy-construction.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeWithRollbackRegisterAdapter(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    return CopySSTIArmyVariableDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00562B10 (FUN_00562B10)
   *
   * What it does:
   * Primary adapter lane that forwards one contiguous
   * `SSTIArmyVariableData` range copy into the canonical rollback helper.
   */
  [[maybe_unused]] void CopySSTIArmyVariableDataRangeWithRollbackAdapterLaneA(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    (void)CopySSTIArmyVariableDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00562FF0 (FUN_00562FF0)
   *
   * What it does:
   * Secondary adapter lane that forwards one contiguous
   * `SSTIArmyVariableData` range copy into the canonical rollback helper.
   */
  [[maybe_unused]] void CopySSTIArmyVariableDataRangeWithRollbackAdapterLaneB(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    (void)CopySSTIArmyVariableDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x005631F0 (FUN_005631F0)
   *
   * What it does:
   * Tertiary adapter lane that forwards one contiguous
   * `SSTIArmyVariableData` range copy into the canonical rollback helper.
   */
  [[maybe_unused]] void CopySSTIArmyVariableDataRangeWithRollbackAdapterLaneC(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    (void)CopySSTIArmyVariableDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007566F0 (FUN_007566F0)
   * Address: 0x00757430 (FUN_00757430, copy_SSTIArmyVariableData_range_with_rollback_alt)
   *
   * What it does:
   * Alternate call-convention lane for the same guarded contiguous
   * `SSTIArmyVariableData` copy-construction routine.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeWithRollbackAlt(
    const moho::SSTIArmyVariableData* sourceBegin,
    const moho::SSTIArmyVariableData* sourceEnd,
    moho::SSTIArmyVariableData* destinationBegin
  )
  {
    return CopySSTIArmyVariableDataRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00753CB0 (FUN_00753CB0)
   *
   * What it does:
   * Register-lane adapter that forwards one guarded
   * `SSTIArmyVariableData` contiguous copy-construction range into the
   * alternate rollback lane.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeWithRollbackAltRegisterAdapterA(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    return CopySSTIArmyVariableDataRangeWithRollbackAlt(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007558F0 (FUN_007558F0)
   *
   * What it does:
   * Secondary register-lane adapter for guarded
   * `SSTIArmyVariableData` contiguous copy-construction into destination
   * storage through the alternate rollback lane.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* CopySSTIArmyVariableDataRangeWithRollbackAltRegisterAdapterB(
    moho::SSTIArmyVariableData* const destinationBegin,
    const moho::SSTIArmyVariableData* const sourceBegin,
    const moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    return CopySSTIArmyVariableDataRangeWithRollbackAlt(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x007519D0 (FUN_007519D0)
   *
   * What it does:
   * Copies one contiguous range `[sourceBegin, sourceEnd)` into destination
   * storage starting at `sourceEnd`.
   */
  [[maybe_unused]] void CopySSTIArmyVariableDataTailRangeWithRollbackAdapter(
    const moho::SSTIArmyVariableData* const sourceBegin,
    moho::SSTIArmyVariableData* const sourceEnd
  )
  {
    (void)CopySSTIArmyVariableDataRangeWithRollbackAlt(sourceBegin, sourceEnd, sourceEnd);
  }

  struct LegacyWordVectorRuntimeView
  {
    void* mAllocProxy;           // +0x00
    std::uint32_t* mBegin;       // +0x04
    std::uint32_t* mEnd;         // +0x08
    std::uint32_t* mCapacityEnd; // +0x0C
  };

  static_assert(sizeof(LegacyWordVectorRuntimeView) == 0x10, "LegacyWordVectorRuntimeView size must be 0x10");

  /**
   * Address: 0x0055FE70 (FUN_0055FE70)
   *
   * What it does:
   * Releases one legacy word-vector backing allocation and clears the
   * begin/end/capacity lanes to the empty-state shape.
   */
  void ResetLegacyWordVectorStorage(LegacyWordVectorRuntimeView* const vectorRuntime)
  {
    if (vectorRuntime->mBegin != nullptr) {
      ::operator delete(vectorRuntime->mBegin);
    }
    vectorRuntime->mBegin = nullptr;
    vectorRuntime->mEnd = nullptr;
    vectorRuntime->mCapacityEnd = nullptr;
  }

  /**
   * Address: 0x00754200 (FUN_00754200, fill_SSTIArmyVariableData_count_with_rollback)
   *
   * What it does:
   * Copy-constructs `count` contiguous `SSTIArmyVariableData` objects from one
   * source payload into destination storage and destroys already-constructed
   * elements before rethrowing if construction fails.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* FillSSTIArmyVariableDataCountWithRollback(
    const unsigned int count,
    moho::SSTIArmyVariableData* destinationBegin,
    const moho::SSTIArmyVariableData* source
  )
  {
    moho::SSTIArmyVariableData* destinationCursor = destinationBegin;
    try {
      for (unsigned int i = 0; i < count; ++i, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          ::new (destinationCursor) moho::SSTIArmyVariableData(*source);
        }
      }
      return destinationCursor;
    } catch (...) {
      for (moho::SSTIArmyVariableData* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->~SSTIArmyVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x007507A0 (FUN_007507A0)
   *
   * What it does:
   * Alternate register-lane adapter that forwards one counted
   * `SSTIArmyVariableData` fill-copy request to the canonical rollback helper.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* FillSSTIArmyVariableDataCountWithRollbackAdapterLaneB(
    const moho::SSTIArmyVariableData* const source,
    moho::SSTIArmyVariableData* const destinationBegin,
    const unsigned int count
  )
  {
    return FillSSTIArmyVariableDataCountWithRollback(count, destinationBegin, source);
  }

  /**
   * Address: 0x00751EC0 (FUN_00751EC0)
   *
   * What it does:
   * Alternate counted-fill adapter lane that forwards
   * `SSTIArmyVariableData` rollback construction into the canonical helper.
   */
  [[maybe_unused]] moho::SSTIArmyVariableData* FillSSTIArmyVariableDataCountWithRollbackAdapterLaneC(
    const moho::SSTIArmyVariableData* const source,
    moho::SSTIArmyVariableData* const destinationBegin,
    const unsigned int count
  )
  {
    return FillSSTIArmyVariableDataCountWithRollback(count, destinationBegin, source);
  }

  [[nodiscard]] moho::SSTIArmyVariableData* CopyConstructSSTIArmyVariableDataIfPresent(
    moho::SSTIArmyVariableData* const destination,
    const moho::SSTIArmyVariableData* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) moho::SSTIArmyVariableData(*source);
  }

  /**
   * Address: 0x00563590 (FUN_00563590)
   *
   * What it does:
   * Primary adapter lane for nullable `SSTIArmyVariableData`
   * copy-construction into caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTIArmyVariableData* CopyConstructSSTIArmyVariableDataIfPresentPrimary(
    moho::SSTIArmyVariableData* const destination,
    const moho::SSTIArmyVariableData* const source
  )
  {
    return CopyConstructSSTIArmyVariableDataIfPresent(destination, source);
  }

  /**
   * Address: 0x00563790 (FUN_00563790)
   *
   * What it does:
   * Secondary adapter lane for nullable `SSTIArmyVariableData`
   * copy-construction into caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTIArmyVariableData* CopyConstructSSTIArmyVariableDataIfPresentSecondary(
    moho::SSTIArmyVariableData* const destination,
    const moho::SSTIArmyVariableData* const source
  )
  {
    return CopyConstructSSTIArmyVariableDataIfPresent(destination, source);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006FD390 (FUN_006FD390, Moho::SSTIArmyVariableData::SSTIArmyVariableData)
   *
   * What it does:
   * Seeds default runtime values for army variable state and constructs the
   * textual/default category lanes expected by serializer/copy callers.
   */
  SSTIArmyVariableData::SSTIArmyVariableData()
    : mIsResourceSharingEnabled(0u)
    , mIsAlly(1u)
    , mPlayerColorBgra(0u)
    , mArmyColorBgra(0u)
    , mArmyType("None")
    , mFaction(0)
    , mUseWholeMap(0u)
    , mShowScore(1u)
    , mIsOutOfGame(0u)
    , mNoRushTimer(0)
    , mNoRushRadius(100.0f)
    , mHandicapValue(1.0f)
    , mHandicapExtra(0.0f)
  {
    std::memset(&mEconomyTotals, 0, sizeof(mEconomyTotals));
    mRuntimeWordVectorWithMeta.mMetaWord = 0u;
    mCategoryFilterSet.ResetToEmpty(0u);
    mArmyStart = Wm3::Vector2f(0.0f, 0.0f);
    mNoRushOffset = Wm3::Vector2f(0.0f, 0.0f);
  }

  /**
   * Address: 0x0055FF80 (FUN_0055FF80, Moho::SSTIArmyVariableData::SSTIArmyVariableData copy-ctor)
   *
   * What it does:
   * Clones army-variable runtime payload lanes, including Set/category bitsets
   * and legacy vector/string state, from one source object.
   */
  SSTIArmyVariableData::SSTIArmyVariableData(const SSTIArmyVariableData& other)
    : mEconomyTotals(other.mEconomyTotals)
    , mIsResourceSharingEnabled(other.mIsResourceSharingEnabled)
    , mNeutrals(other.mNeutrals)
    , mAllies(other.mAllies)
    , mEnemies(other.mEnemies)
    , mIsAlly(other.mIsAlly)
    , mValidCommandSources(other.mValidCommandSources)
    , mPlayerColorBgra(other.mPlayerColorBgra)
    , mArmyColorBgra(other.mArmyColorBgra)
    , mArmyType(other.mArmyType)
    , mFaction(other.mFaction)
    , mUseWholeMap(other.mUseWholeMap)
    , mShowScore(other.mShowScore)
    , mCategoryFilterSet(other.mCategoryFilterSet)
    , mIsOutOfGame(other.mIsOutOfGame)
    , mArmyStart(other.mArmyStart)
    , mNoRushTimer(other.mNoRushTimer)
    , mNoRushRadius(other.mNoRushRadius)
    , mNoRushOffset(other.mNoRushOffset)
    , mHandicapValue(other.mHandicapValue)
    , mHandicapExtra(other.mHandicapExtra)
  {
    std::memcpy(mPad_0039_0040, other.mPad_0039_0040, sizeof(mPad_0039_0040));
    std::memcpy(mPad_00A1_00A8, other.mPad_00A1_00A8, sizeof(mPad_00A1_00A8));
    std::memcpy(mPad_00F1_00F4, other.mPad_00F1_00F4, sizeof(mPad_00F1_00F4));
    std::memcpy(mRuntimePad_0109_0110, other.mRuntimePad_0109_0110, sizeof(mRuntimePad_0109_0110));
    std::memcpy(mPad_0139_013C, other.mPad_0139_013C, sizeof(mPad_0139_013C));
    std::memcpy(mPad_015C_0160, other.mPad_015C_0160, sizeof(mPad_015C_0160));

    mRuntimeWordVectorWithMeta.CopyWordPayloadFrom(other.mRuntimeWordVectorWithMeta);
    mRuntimeWordVectorWithMeta.mMetaWord = other.mRuntimeWordVectorWithMeta.mMetaWord;
  }

  /**
   * Address: 0x0055FEA0 (FUN_0055FEA0, Moho::SSTIArmyVariableData::~SSTIArmyVariableData)
   *
   * What it does:
   * Tears down set/vector/string member lanes for one army-variable payload.
   */
  SSTIArmyVariableData::~SSTIArmyVariableData() = default;

  /**
   * Address: 0x00561590 (FUN_00561590)
   *
   * What it does:
   * Destroys one contiguous `SSTIArmyVariableData` range `[begin, end)` by
   * invoking the element destructor in forward order.
   */
  [[maybe_unused]] void DestroySSTIArmyVariableDataRange(
    SSTIArmyVariableData* begin,
    SSTIArmyVariableData* const end
  )
  {
    while (begin != end) {
      begin->~SSTIArmyVariableData();
      ++begin;
    }
  }

  /**
   * Address: 0x007011C0 (FUN_007011C0)
   */
  void SArmyVectorWithMeta::CopyWordPayloadFrom(const SArmyVectorWithMeta& source)
  {
    if (this == &source) {
      return;
    }

    mWords.resize(source.mWords.size());
    (void)CopyWordRangeForward(mWords.data(), source.mWords.data(), source.mWords.data() + source.mWords.size());
  }

  /**
   * Address: 0x00551270 (FUN_00551270, Moho::SSTIArmyVariableDataSerializer::Deserialize)
   */
  void SSTIArmyVariableData::SerializeLoadBody(gpg::ReadArchive* const archive, gpg::RRef* const ownerRef)
  {
    if (archive == nullptr) {
      return;
    }

    DeserializeObjectByRTypeName(archive, &mEconomyTotals, {"SEconTotals", "Moho::SEconTotals"}, ownerRef);

    bool boolValue = false;
    archive->ReadBool(&boolValue);
    mIsResourceSharingEnabled = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mNeutrals, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    DeserializeObjectByRTypeName(archive, &mAllies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    DeserializeObjectByRTypeName(archive, &mEnemies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->ReadBool(&boolValue);
    mIsAlly = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mValidCommandSources, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->ReadUInt(&mPlayerColorBgra);
    archive->ReadUInt(&mArmyColorBgra);
    archive->ReadString(&mArmyType);
    archive->ReadInt(&mFaction);

    archive->ReadBool(&boolValue);
    mUseWholeMap = boolValue ? 1u : 0u;

    archive->ReadBool(&boolValue);
    mShowScore = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(
      archive,
      &mCategoryFilterSet,
      {"BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "Moho::BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "BVSet<RBlueprint const *,EntityCategoryHelper>"},
      ownerRef
    );

    archive->ReadBool(&boolValue);
    mIsOutOfGame = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mArmyStart, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->ReadInt(&mNoRushTimer);
    archive->ReadFloat(&mNoRushRadius);
    DeserializeObjectByRTypeName(archive, &mNoRushOffset, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->ReadFloat(&mHandicapValue);
    archive->ReadFloat(&mHandicapExtra);
  }

  /**
   * Address: 0x00551500 (FUN_00551500, Moho::SSTIArmyVariableDataSerializer::Serialize)
   */
  void SSTIArmyVariableData::SerializeSaveBody(gpg::WriteArchive* const archive, gpg::RRef* const ownerRef) const
  {
    if (archive == nullptr) {
      return;
    }

    SerializeObjectByRTypeName(archive, &mEconomyTotals, {"SEconTotals", "Moho::SEconTotals"}, ownerRef);
    archive->WriteBool(mIsResourceSharingEnabled != 0u);

    SerializeObjectByRTypeName(archive, &mNeutrals, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    SerializeObjectByRTypeName(archive, &mAllies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    SerializeObjectByRTypeName(archive, &mEnemies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->WriteBool(mIsAlly != 0u);
    SerializeObjectByRTypeName(archive, &mValidCommandSources, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->WriteUInt(mPlayerColorBgra);
    archive->WriteUInt(mArmyColorBgra);
    archive->WriteString(const_cast<msvc8::string*>(&mArmyType));
    archive->WriteInt(mFaction);
    archive->WriteBool(mUseWholeMap != 0u);
    archive->WriteBool(mShowScore != 0u);

    SerializeObjectByRTypeName(
      archive,
      &mCategoryFilterSet,
      {"BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "Moho::BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "BVSet<RBlueprint const *,EntityCategoryHelper>"},
      ownerRef
    );

    archive->WriteBool(mIsOutOfGame != 0u);
    SerializeObjectByRTypeName(archive, &mArmyStart, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->WriteInt(mNoRushTimer);
    archive->WriteFloat(mNoRushRadius);
    SerializeObjectByRTypeName(archive, &mNoRushOffset, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->WriteFloat(mHandicapValue);
    archive->WriteFloat(mHandicapExtra);
  }

  /**
   * Address: 0x00550A00 (FUN_00550A00, Moho::SSTIArmyVariableDataSerializer::Deserialize callback)
   *
   * What it does:
   * Archive callback thunk forwarding into `SSTIArmyVariableData::SerializeLoadBody`.
   */
  void SSTIArmyVariableDataSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const data = reinterpret_cast<SSTIArmyVariableData*>(objectPtr);
    GPG_ASSERT(data != nullptr);
    if (ownerRef != nullptr) {
      data->SerializeLoadBody(archive, ownerRef);
      return;
    }

    SSTIArmyVariableDataMemberDeserializeThunk(data, archive);
  }

  /**
   * Address: 0x00550A10 (FUN_00550A10, Moho::SSTIArmyVariableDataSerializer::Serialize callback)
   *
   * What it does:
   * Archive callback thunk forwarding into `SSTIArmyVariableData::SerializeSaveBody`.
   */
  void SSTIArmyVariableDataSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const data = reinterpret_cast<const SSTIArmyVariableData*>(objectPtr);
    GPG_ASSERT(data != nullptr);
    if (ownerRef != nullptr) {
      data->SerializeSaveBody(archive, ownerRef);
      return;
    }

    SSTIArmyVariableDataMemberSerializeThunk(data, archive);
  }

  /**
   * Address: 0x00550D90 (FUN_00550D90, sub_550D90)
   */
  void SSTIArmyVariableDataSerializer::RegisterSerializeFunctions()
  {
    if (mSerLoadFunc == nullptr) {
      mSerLoadFunc = &SSTIArmyVariableDataSerializer::Deserialize;
    }
    if (mSerSaveFunc == nullptr) {
      mSerSaveFunc = &SSTIArmyVariableDataSerializer::Serialize;
    }

    gpg::RType* const type = gpg::LookupRType(typeid(SSTIArmyVariableData));
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00BC9B10 (FUN_00BC9B10, register_SSTIArmyVariableDataSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for
   * `SSTIArmyVariableData` and schedules process-exit cleanup.
   */
  void register_SSTIArmyVariableDataSerializer()
  {
    InitializeHelperNode(gSSTIArmyVariableDataSerializer);
    gSSTIArmyVariableDataSerializer.mSerLoadFunc = &SSTIArmyVariableDataSerializer::Deserialize;
    gSSTIArmyVariableDataSerializer.mSerSaveFunc = &SSTIArmyVariableDataSerializer::Serialize;
    (void)std::atexit(&CleanupSSTIArmyVariableDataSerializerAtexit);
  }

  /**
   * Address: 0x005508C0 (FUN_005508C0, startup typeinfo constructor lane)
   */
  SSTIArmyVariableDataTypeInfo::SSTIArmyVariableDataTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SSTIArmyVariableData), this);
  }

  /**
   * Address: 0x00550950 (FUN_00550950, sub_550950)
   */
  SSTIArmyVariableDataTypeInfo::~SSTIArmyVariableDataTypeInfo() = default;

  /**
   * Address: 0x00550940 (FUN_00550940, sub_550940)
   */
  const char* SSTIArmyVariableDataTypeInfo::GetName() const
  {
    return "SSTIArmyVariableData";
  }

  /**
   * Address: 0x00550920 (FUN_00550920, sub_550920)
   */
  void SSTIArmyVariableDataTypeInfo::Init()
  {
    size_ = sizeof(SSTIArmyVariableData);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC9AF0 (FUN_00BC9AF0, register_SSTIArmyVariableDataTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `SSTIArmyVariableDataTypeInfo` storage and
   * registers process-exit teardown.
   */
  void register_SSTIArmyVariableDataTypeInfo()
  {
    (void)AcquireSSTIArmyVariableDataTypeInfo();
    (void)std::atexit(&CleanupSSTIArmyVariableDataTypeInfoAtexit);
  }
} // namespace moho

namespace
{
  struct SSTIArmyVariableDataTypeInfoBootstrap
  {
    SSTIArmyVariableDataTypeInfoBootstrap()
    {
      moho::register_SSTIArmyVariableDataTypeInfo();
    }
  };

  [[maybe_unused]] SSTIArmyVariableDataTypeInfoBootstrap gSSTIArmyVariableDataTypeInfoBootstrap;

  struct SSTIArmyVariableDataSerializerBootstrap
  {
    SSTIArmyVariableDataSerializerBootstrap()
    {
      moho::register_SSTIArmyVariableDataSerializer();
    }
  };

  [[maybe_unused]] SSTIArmyVariableDataSerializerBootstrap gSSTIArmyVariableDataSerializerBootstrap;
} // namespace
