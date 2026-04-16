#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/command/SSTITarget.h"
#include "moho/sim/SOCellPos.h"

#ifndef FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_ENFORCE_STRICT_LAYOUT_ASSERTS 0
#endif

#ifndef FAF_RUNTIME_LAYOUT_ASSERT
#if FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_RUNTIME_LAYOUT_ASSERT(...) static_assert(__VA_ARGS__)
#else
#define FAF_RUNTIME_LAYOUT_ASSERT(...)
#endif
#endif
namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  struct SSTICommandIssueData;
  using EntId = std::int32_t;

  struct SSTICommandVariableData
  {
    static gpg::RType* sType;

    msvc8::vector<EntId> mEntIds;
    std::int32_t v1;
    std::int32_t v2;
    EUnitCommandType mCmdType;
    SSTITarget mTarget1;
    SSTITarget mTarget2;
    std::int32_t v14;
    msvc8::vector<SOCellPos> mCells;
    std::int32_t v19;
    std::int32_t v20;
    std::int32_t mMaxCount;
    std::int32_t mCount;
    std::uint32_t v23;

    /**
     * Address: 0x00552A00 (FUN_00552A00, Moho::SSTICommandVariableData::SSTICommandVariableData)
     *
     * What it does:
     * Initializes command-variable payload lanes to default/empty command state
     * (`None` targets, empty vectors, and unset count limits).
     */
    SSTICommandVariableData();

    /**
     * Address: 0x006ECAD0 (FUN_006ECAD0, Moho::SSTICommandVariableData::SSTICommandVariableData)
     *
     * What it does:
     * Copy-constructs the full command-variable payload including target lanes
     * and variable cell vector storage.
     */
    SSTICommandVariableData(const SSTICommandVariableData& other);

    /**
     * Address: 0x00552A70 (FUN_00552A70, Moho::SSTICommandVariableData::SSTICommandVariableData)
     *
     * What it does:
     * Initializes variable-payload lanes from one command-issue payload
     * (`mCmdType`, both targets, cell list, and count limits).
     */
    explicit SSTICommandVariableData(const SSTICommandIssueData& issueData);

    /**
     * Address: 0x005603E0 (FUN_005603E0, Moho::SSTICommandVariableData::~SSTICommandVariableData)
     *
     * What it does:
     * Releases command payload vectors (`mCells`, `mEntIds`) and restores their
     * inline-storage lanes.
     */
    ~SSTICommandVariableData();

    /**
     * Address: 0x00554760 (FUN_00554760, Moho::SSTICommandVariableData::MemberDeserialize)
     *
     * What it does:
     * Loads one command-variable payload lane from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005548A0 (FUN_005548A0, Moho::SSTICommandVariableData::MemberSerialize)
     *
     * What it does:
     * Stores one command-variable payload lane to archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  class SSTICommandVariableDataSerializer
  {
  public:
    /**
     * Address: 0x00552B20 (FUN_00552B20, Moho::SSTICommandVariableDataSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-load callback flow into `SSTICommandVariableData::MemberDeserialize`.
     */
    static void Serialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00552B30 (FUN_00552B30, Moho::SSTICommandVariableDataSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-save callback flow into `SSTICommandVariableData::MemberSerialize`.
     */
    static void Deserialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00553260 (FUN_00553260, gpg::SerSaveLoadHelper_SSTICommandVariableData::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SSTICommandVariableData` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SSTICommandVariableData, mEntIds) == 0x00, "SSTICommandVariableData::mEntIds offset must be 0x00");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SSTICommandVariableData, v1) == 0x10, "SSTICommandVariableData::v1 offset must be 0x10");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SSTICommandVariableData, v2) == 0x14, "SSTICommandVariableData::v2 offset must be 0x14");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, mCmdType) == 0x18, "SSTICommandVariableData::mCmdType offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, mTarget1) == 0x1C, "SSTICommandVariableData::mTarget1 offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, mTarget2) == 0x30, "SSTICommandVariableData::mTarget2 offset must be 0x30"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, v14) == 0x44, "SSTICommandVariableData::v14 offset must be 0x44"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, mCells) == 0x48, "SSTICommandVariableData::mCells offset must be 0x48"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, mMaxCount) == 0x60, "SSTICommandVariableData::mMaxCount offset must be 0x60"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, mCount) == 0x64, "SSTICommandVariableData::mCount offset must be 0x64"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableData, v23) == 0x68, "SSTICommandVariableData::v23 offset must be 0x68"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableDataSerializer, mHelperNext) == 0x04,
    "SSTICommandVariableDataSerializer::mHelperNext offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableDataSerializer, mHelperPrev) == 0x08,
    "SSTICommandVariableDataSerializer::mHelperPrev offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableDataSerializer, mSerLoadFunc) == 0x0C,
    "SSTICommandVariableDataSerializer::mSerLoadFunc offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SSTICommandVariableDataSerializer, mSerSaveFunc) == 0x10,
    "SSTICommandVariableDataSerializer::mSerSaveFunc offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    sizeof(SSTICommandVariableDataSerializer) == 0x14, "SSTICommandVariableDataSerializer size must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SSTICommandVariableData) == 0x70, "SSTICommandVariableData size must be 0x70");

  /**
   * Address: 0x005528C0 (FUN_005528C0, preregister_SSTICommandVariableDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandVariableData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTICommandVariableDataTypeInfo();
} // namespace moho
